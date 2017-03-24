import copy
import enum

from flask import request
from flask_security import login_user, logout_user
import pytest

from bayesian.auth import LazyRowBasedPermission, Permission, Role, User, require_permissions
from bayesian.exceptions import HTTPError


class PermEnumTesting(enum.Enum):
    go_to_bed = 'go_to_bed'
    lay_on_couch = 'lay_on_couch'
    have_a_nap = 'have_a_nap'

users = [
    User(login='user0'),
    User(login='user1'),
    User(login='user2'),
]

permissions = [Permission(name=val.name) for val in PermEnumTesting]

roles = [
    Role(name='early bird'),
    Role(name='lazybones'),
    Role(name='sluggard'),
]


@pytest.fixture
def fill_users(rdb):
    loc_users = copy.deepcopy(users)
    for u in loc_users:
        rdb.session.add(u)
    rdb.session.commit()
    return loc_users


@pytest.fixture
def fill_permissions(rdb):
    loc_permissions = copy.deepcopy(permissions)
    for p in loc_permissions:
        rdb.session.add(p)
    rdb.session.commit()
    return loc_permissions


@pytest.fixture
def fill_roles(rdb):
    loc_roles = copy.deepcopy(roles)
    for r in loc_roles:
        rdb.session.add(r)
    rdb.session.commit()
    return loc_roles


@pytest.fixture
def fill_auth_data(rdb):
    us = fill_users(rdb)
    ps = fill_permissions(rdb)
    rs = fill_roles(rdb)

    # no roles for user0
    us[1].roles = [rs[0], rs[1]]
    us[2].roles = [rs[2]]

    # no roles for early bird
    rs[1].permissions = [ps[1], ps[2]]
    rs[2].permissions = [ps[0]]

    rdb.session.commit()


@pytest.mark.usefixtures('client_class', 'rdb')
class TestRequirePermissions(object):
    def setup_method(self, method):
        self.l = lambda: 'success'

    def users(self, rdb):
        return list(rdb.session.query(User).order_by(User.login.asc()))

    def test_no_permissions_required_allows_all_users(self, fill_auth_data, rdb):
        # test unauthenticated user
        assert require_permissions()(self.l)() == 'success'

        for u in self.users(rdb):
            login_user(u)
            assert require_permissions()(self.l)() == 'success'
            logout_user()

    def test_require_permissions_and(self, fill_auth_data, rdb):
        us = self.users(rdb)
        rq = [PermEnumTesting.have_a_nap, PermEnumTesting.lay_on_couch]

        # test unauthenticated user
        with pytest.raises(HTTPError):
            require_permissions(*rq)(self.l)()

        for i in [0, 2]:
            login_user(us[i])
            with pytest.raises(HTTPError):
                require_permissions(*rq)(self.l)()
            logout_user()

        login_user(us[1])
        assert require_permissions(*rq)(self.l)() == 'success'
        logout_user()

    def test_require_permissions_or(self, fill_auth_data, rdb):
        us = self.users(rdb)
        rq = [[PermEnumTesting.go_to_bed, PermEnumTesting.lay_on_couch]]

        # test unauthenticated user
        with pytest.raises(HTTPError):
            require_permissions(*rq)(self.l)()

        login_user(us[0])
        with pytest.raises(HTTPError):
            require_permissions(*rq)(self.l)()
        logout_user()

        for i in [1, 2]:
            login_user(us[i])
            assert require_permissions(*rq)(self.l)() == 'success'
            logout_user()

    def test_require_permissions_complex(self, fill_auth_data, rdb):
        us = self.users(rdb)
        rq = [PermEnumTesting.lay_on_couch,
              [PermEnumTesting.have_a_nap, PermEnumTesting.go_to_bed]]

        # test unauthenticated user
        with pytest.raises(HTTPError):
            require_permissions(*rq)(self.l)()

        login_user(us[1])
        assert require_permissions(*rq)(self.l)() == 'success'

        for i in [0, 2]:
            login_user(us[i])
            with pytest.raises(HTTPError):
                require_permissions(*rq)(self.l)()
            logout_user()

    def test_with_lazy_row_based_permission(self, fill_auth_data, rdb):
        us = self.users(rdb)

        class AccessBedPermission(LazyRowBasedPermission):
            def allows(self, identity):
                # let's pretend that this accesses some DB table and uses self.get_atr()...
                if identity.id == us[2].id:
                    # only sluggard can make bed
                    return True
                return False

        rq = [AccessBedPermission()]
        # test unauthenticated user
        with pytest.raises(HTTPError):
            require_permissions(*rq)(self.l)()

        for i in [0, 1]:
            login_user(us[i])
            # test calling by require_permissions decorator
            with pytest.raises(HTTPError):
                require_permissions(*rq)(self.l)()
            # test calling by hand
            assert rq[0].can() is False
            logout_user()

        login_user(us[2])
        # test calling by require_permissions decorator
        assert require_permissions(*rq)(self.l)() == 'success'
        # test calling by hand
        assert rq[0].can() is True


@pytest.mark.usefixtures('client_class')
class TestLazyRowBasedPermission:
    def test_get_arg(self):
        l = LazyRowBasedPermission(need=3)
        assert l.get_arg() == 3
        l = LazyRowBasedPermission(view_arg='foo')
        request.view_args['foo'] = 3
        assert l.get_arg() == 3

        class X(LazyRowBasedPermission):
            view_arg = 'foo'

        l = X()
        assert l.get_arg() == 3

    def test_str(self):
        class Y(LazyRowBasedPermission):
            name = 'do stuff with {arg}'

        assert str(Y(need=123)) == 'do stuff with 123'

        class X(Y):
            def get_arg(self):
                raise KeyError('got you!')

        assert str(X()) == 'do stuff with unknown'
