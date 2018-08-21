"""Authorization token handling."""

import datetime

from flask import current_app
from flask_security import UserMixin
from itsdangerous import BadSignature, SignatureExpired, TimedJSONWebSignatureSerializer

from . import rdb
from .exceptions import HTTPError


class APIUser(UserMixin):
    """Structure representing user accessing the API."""

    def __init__(self, email):
        """Construct the instance of APIUsed class and initialize the 'email' attribute."""
        self.email = email


class User(rdb.Model, UserMixin):
    """Structure representing user accessing the system using its security token ."""

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
        """Generate new security token.

        Note: calling this automatically rewrites (== revokes) previous token.
        """
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
        """Revoke security token."""
        self.token = None
        self.token_expires = None
        rdb.session.add(self)
        rdb.session.commit()

    @classmethod
    def get_by_token(cls, token):
        """Find the owner of given security token."""
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
