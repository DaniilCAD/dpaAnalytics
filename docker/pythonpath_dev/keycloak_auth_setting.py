from flask import redirect, request
from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from flask_appbuilder.security.sqla.models import User, Model
from urllib.parse import quote
from flask_appbuilder.views import ModelView, SimpleFormView, expose
import logging
from sqlalchemy import (
    Column,
    String,
)

logger = logging.getLogger()


class CustomUser(User):
    __tablename__ = 'ab_user'
    main_inn = Column(String(12))
    head_inn = Column(String(12))


class OIDCSecurityManager(SupersetSecurityManager):

    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
        self.authoidview = AuthOIDCView

    def add_user(self, username, first_name, last_name, email, roles, main_inn=None,
                 head_inn=None):
        user = self.find_user(username=username)
        if not user:
            user = CustomUser()
            user.first_name = first_name
            user.last_name = last_name
            user.username = username
            user.email = email
            user.main_inn = main_inn
            user.head_inn = head_inn
            if not isinstance(roles, (list, set, tuple)):
                roles = [roles]
            self.get_session.add(user)
            self.get_session.commit()
        return user


class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        oidc = sm.oid
        superset_roles = ["Admin", "Alpha", "Gamma", "Public", "granter", "sql_lab"]
        default_role = "Gamma"

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))
            user = sm.auth_user_oid(oidc.user_getfield('email'))
            if user is None:
                info = oidc.user_getinfo(
                    ['preferred_username', 'given_name', 'family_name', 'email',
                     'roles', 'inn', 'headINNName'])
                roles = [role for role in superset_roles if
                         role in info.get('roles', [])]
                roles += [default_role, ] if not roles else []
                user = sm.add_user(info.get('preferred_username'),
                                   info.get('given_name'), info.get('family_name'),
                                   info.get('email'),
                                   [sm.find_role(role) for role in roles],
                                   main_inn=info.get('inn'),
                                   head_inn=info.get('headINNName'))

            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid

        oidc.logout()
        super(AuthOIDCView, self).logout()
        redirect_uri = 'http://158.160.81.201:8000/225-2/'
        return redirect(redirect_uri)
