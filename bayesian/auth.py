import datetime
import enum

from flask import current_app, request, g
from flask_principal import Permission as PrincipalPermission
from flask_security import RoleMixin, UserMixin, current_user, login_user
from itsdangerous import BadSignature, SignatureExpired, TimedJSONWebSignatureSerializer
import jwt
from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
from os import getenv
from sqlalchemy.exc import SQLAlchemyError

from . import rdb
from .exceptions import HTTPError
from .utils import fetch_public_key

jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))


def decode_token():
    token = request.headers.get('Authorization')
    if token is None:
        return token

    if token.startswith('Bearer '):
        _, token = token.split(' ', 1)

    pub_key = fetch_public_key(current_app)
    audiences = current_app.config.get('BAYESIAN_JWT_AUDIENCE').split(',')
    aud_len = len(audiences)
    for aud in audiences:
        try:
            decoded_token = jwt.decode(token, pub_key, audience=aud)
        except jwt.InvalidTokenError:
            current_app.logger.error('Auth Token could not be decoded for audience {}'.format(aud))
            decoded_token = None

        if decoded_token is not None:
            break

    if decoded_token is None:
        raise jwt.InvalidTokenError('Auth token audience cannot be verified.')

    return decoded_token


def login_required(view):
    # NOTE: the actual authentication 401 failures are commented out for now and will be
    # uncommented as soon as we know everything works fine; right now this is purely for
    # being able to tail logs and see if stuff is going fine
    def wrapper(*args, **kwargs):
        # Disable authentication for local setup
        if getenv('DISABLE_AUTHENTICATION') in ('1', 'True', 'true'):
            return view(*args, **kwargs)

        lgr = current_app.logger
        user = None

        try:
            decoded = decode_token()
            if decoded is None:
                lgr.exception('Provide an Authorization token with the API request')
                raise HTTPError(401, 'Authentication failed - token missing')

            lgr.info('Successfuly authenticated user {e} using JWT'.
                     format(e=decoded.get('email')))
        except jwt.ExpiredSignatureError as exc:
            lgr.exception('Expired JWT token')
            decoded = {'email': 'unauthenticated@jwt.failed'}
            raise HTTPError(401, 'Authentication failed - token has expired') from exc
        except Exception as exc:
            lgr.exception('Failed decoding JWT token')
            decoded = {'email': 'unauthenticated@jwt.failed'}
            raise HTTPError(401, 'Authentication failed - could not decode JWT token') from exc
        else:
            user = APIUser(decoded.get('email', 'nobody@nowhere.nodomain'))

        if user:
            g.current_user = user
        else:
            g.current_user = APIUser('unauthenticated@no.auth.token')
            raise HTTPError(401, 'Authentication required')
        return view(*args, **kwargs)
    return wrapper


class APIUser(UserMixin):
    def __init__(self, email):
        self.email = email


# NOTE: the stuff below is obsolete and we'll most likely want to drop it in future
roles_users = rdb.Table('roles_users',
                        rdb.Column('user_id', rdb.Integer(), rdb.ForeignKey('user.id')),
                        rdb.Column('role_id', rdb.Integer(), rdb.ForeignKey('role.id')))


permissions_roles = rdb.Table('permissions_roles',
                              rdb.Column('role_id', rdb.Integer(), rdb.ForeignKey('role.id')),
                              rdb.Column('permission_id', rdb.Integer(),
                                         rdb.ForeignKey('permission.id')))


class LazyRowBasedPermission(PrincipalPermission):
    """This class represents a lazily-checked row-based permission. You'll need to create
    a subclass for specific checks. E.g. you may want to create a subclass that will
    express permission based on who created DB object Foo:

        class ModifyFooPermission(LazyRowBasedPermission):
            name = 'modify Foo id {arg}'  # this always has to contain "{arg}"
            view_arg = 'foo_id'

            def allows(self, identity):
                # identity contains id of logged-in user, but it can also be
                #  AnonymousIdentity, which has no id
                # if you're going to use this after @login_required decorator,
                #  you'll never get AnonymousIdentity
                arg = self.get_arg()
                foo = rdb.session.query(Foo).get(arg)
                if foo is None:
                    raise HTTPError(404, 'foo {id} not found'.format(id=arg))
                return foo.created_by == identity.id

        modify_foo_permission = ModifyFooPermission()

        # you can use modify_foo_permission as argument to require_permissions decorator
        @app.route('/foo/<int:foo_id>', methods=['POST'])
        @require_permissions(modify_foo_permission)
        def edit_foo(foo_id):
            # will only get here if current user created Foo object with id foo_id
            pass

        # alternatively, if you need to check the permission inside the view:
        @app.route('/foo/<something>', method=['POST'])
        def edit_foo(something):
            foo_id = complex_computation(something)
            if ModifyFooPermission(need=foo_id).can():  # "can" calls "allows" for current user
                pass  # do something
            else:
                raise HTTPError(403, 'No way, amigo')

    This implementation uses one of the proposals for flask-principal lazy permissions as a base:
        https://github.com/mattupstate/flask-principal/issues/6#issuecomment-24750550
    """
    name = 'modify row {arg}'
    view_arg = None

    def __init__(self, need=None, view_arg=None):
        super().__init__(self, *[need])
        self.only_need = need  # we only assume one need for our permissions ATM
        self.view_arg = view_arg or type(self).view_arg

    def get_arg(self):
        """Get the arg from self.only_need or from request"""
        return self.only_need or request.view_args.get(self.view_arg)

    def __str__(self):
        try:
            arg = self.get_arg()
        except:
            arg = 'unknown'
        return self.name.format(arg=arg)


def _check_one_perm(perm, has_perms):
    """Helper function that evaluates one permission (be it PermEnum instance or
    LazyRowBasedPermission instance) and returns True/False."""
    if isinstance(perm, enum.Enum):
        return perm.value in has_perms
    elif isinstance(perm, LazyRowBasedPermission):
        return perm.can()
    else:
        raise HTTPError(500, 'Internal server error while checking permissions')


def check_permissions_and(needs_perms, has_perms):
    """Checks if all permissions from list `needs_perms` are satisfied.
    Returns `None` if check succeeds, raises `HTTPError` with 403 code otherwise (logical "and").

    Members of the `needs_perms` list can be:
    * PermEnum instances - it is checked whether or not their string names are in `has_perms` list
    * LazyRowBasedPermission instances - it is checked that they allow currently logged in user to
      perform the action
    * list/tuple instances - interpreted as logical "or" and passed to `check_permissions_or`

    :param needs_perms: (nested) list of strings, permissions to check for
    :param has_perms: list of strings, permissions to check against
    """
    for perm in needs_perms:
        if isinstance(perm, (list, tuple)):
            check_permissions_or(perm, has_perms)
        else:
            if not _check_one_perm(perm, has_perms):
                raise HTTPError(403, 'User doesn\'t have permission "{}"'.format(str(perm)))
            # else everything is fine


def check_permissions_or(needs_perms, has_perms):
    """Checks if at least one permission from list `needs_perms` is satisfied.
    Returns `None` if check succeeds, raises `HTTPError` with 403 code otherwise (logical "or").

    Members of the `needs_perms` list follow the same rules as for `check_permissions_and`,
    except list/tuple instances get interpreted as logical "and" and passed
    to `check_permissions_and`.

    :param needs_perms: (nested) list of strings, permissions to check for
    :param has_perms: list of strings, permissions to check against
    """
    for perm in needs_perms:
        if isinstance(perm, (list, tuple)):
            try:
                check_permissions_and(perm, has_perms)
                return
            except HTTPError:
                pass  # continue to check following need
        else:
            if _check_one_perm(perm, has_perms):
                return
            # else continue to check following need
    raise HTTPError(403, 'User doesn\'t have any permission of required: "{}"'.format(needs_perms))


def require_permissions(*needs_perms):
    """View decorator which checks that current user has sufficient permissions to access
    the decorated view. Raises HTTPError with 403 status code if not.

    User's permissions are
    * all permissions of all roles that the user currently has assigned (string representations
      of PermEnum instances)
    * dynamic permissions based on current DB content (represented by instances of subclasses
      of LazyRowBasedPermission)

    :param needs_perms: PermEnum/LazyRowBasedPermission instances or (nested) lists of
        PermEnum/LazyRowBasedPermission instances

    Explanation:
        The needs_perms argument allows expressing arbitrary permission requirements using
        logical "and" and "or" by nesting. Even levels of nesting (0th, 2nd, ...) express
        "and", odd levels (1st, 3rd, ...) express "or". For example:

        # this example uses numbers to keep it concise
        - require_permissions(1) ~> require "1"
        - require_permissions(1, 2) ~> require "1 and 2"
        - require_permissions([3, 4]) ~> require "3 or 4"
        - require_permissions(1, 2, [3, 4]) ~> require "1 and 2 and (3 or 4)"
        - require_permissions(1, [2, [3, 4]]) ~> require "1 and (2 or (3 and 4))"

        # a real example would look like this:
        @require_permissions(PermEnum.sleep, [PermEnum.lay_on_couch, PermEnum.lay_on_bed])
        @app.route('/sleep')
        def sleep():
            return 'sleeping!'
        # user must has following permissions to be able to access the view:
        #   (permission to sleep and (permission to lay on couch or permission to lay on bed))

    """
    def func_decorator(func):
        def inner(*args, **kwargs):
            if needs_perms:
                if not current_user.is_authenticated:
                    raise HTTPError(401, 'Unauthenticated user can\'t access this view')
                # get all user permissions from DB
                try:
                    user = rdb.session.query(User).\
                                       outerjoin(User.roles).\
                                       outerjoin(Role.permissions).\
                                       filter(User.id == current_user.id).first()
                except SQLAlchemyError:
                    rdb.session.rollback()
                    raise
                has_perms = []
                for role in user.roles:
                    for perm in role.permissions:
                        has_perms.append(perm.name)
                check_permissions_and(needs_perms, has_perms)
            # else no permissions are needed => don't check anything
            return func(*args, **kwargs)
        return inner
    return func_decorator


class PermEnum(enum.Enum):
    # NOTE: when adding/changing/deleting these, you need to manually create a migration that
    #   adds/updates/deletes the appropriate Permission row in DB
    def __str__(self):
        return self.value


class Permission(rdb.Model):
    id = rdb.Column(rdb.Integer(), primary_key=True)
    name = rdb.Column(rdb.String(80), unique=True)


class Role(rdb.Model, RoleMixin):
    id = rdb.Column(rdb.Integer(), primary_key=True)
    name = rdb.Column(rdb.String(80), unique=True)
    description = rdb.Column(rdb.String(255))
    permissions = rdb.relationship('Permission', secondary=permissions_roles,
                                   backref=rdb.backref('roles', lazy='dynamic'))


class User(rdb.Model, UserMixin):
    id = rdb.Column(rdb.Integer(), primary_key=True)
    login = rdb.Column(rdb.String(255), unique=True)
    email = rdb.Column(rdb.String(255))
    password = rdb.Column(rdb.String(255))
    active = rdb.Column(rdb.Boolean(), default=True)
    roles = rdb.relationship('Role', secondary=roles_users,
                             backref=rdb.backref('users', lazy='dynamic'))
    token = rdb.Column(rdb.String(255))
    token_expires = rdb.Column(rdb.DateTime())

    def generate_auth_token(self, expiration=None):
        """Note: calling this automatically rewrites (== revokes) previous token."""
        expires_in = expiration or current_app.config['API_TOKEN_LIFETIME']
        s = TimedJSONWebSignatureSerializer(current_app.config['SECRET_KEY'],
                                            expires_in=expires_in)
        self.token = s.dumps({'id': str(self.id)})
        # time based signers in itsdangerous always return bytes, so we decode to store in DB
        #   (there should be no harm done storing the token decoded)
        self.token = self.token.decode('utf-8')
        # we need to store the token expiration time since user may change it by revoking the token
        self.token_expires = s.get_issue_date(s.loads(self.token, return_header=True)[1]) + \
            datetime.timedelta(seconds=expires_in)
        rdb.session.add(self)
        rdb.session.commit()
        return self.token, self.token_expires

    def revoke_auth_token(self):
        self.token = None
        self.token_expires = None
        rdb.session.add(self)
        rdb.session.commit()

    @classmethod
    def get_by_token(cls, token):
        s = TimedJSONWebSignatureSerializer(current_app.config['SECRET_KEY'])
        # may raise BadSignature or SignatureExpired
        data = s.loads(token)
        user = current_app.user_datastore.find_user(id=data['id'])
        if not user:
            raise HTTPError(401, 'Unknow user with id {}'.format(data['id']))
        if user.token == token:
            if datetime.datetime.utcnow() < user.token_expires:
                return user
            raise SignatureExpired('bad token')
        raise BadSignature('bad token')
