from flask import redirect, flash
from flask_appbuilder import expose
from flask_appbuilder.security.manager import AUTH_OID
from sqlalchemy import Column, String
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user, logout_user
from flask_appbuilder.security.sqla.models import User
import logging
from sqlalchemy.exc import SQLAlchemyError
from flask_login import current_user

logger = logging.getLogger()


def get_current_user_main_inn():
    return current_user.main_inn


def get_current_user_head_inn():
    return current_user.head_inn


# Custom User class
class CustomUser(User):
    __tablename__ = 'ab_user'
    main_inn = Column(String(64))
    head_inn = Column(String(64))


# OIDC Security Manager
class OIDCSecurityManager(SupersetSecurityManager):
    user_model = CustomUser

    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
        self.authoidview = AuthOIDCView

    def add_user(self, username, first_name, last_name, email, role, password='',
                 main_inn=None, head_inn=None, active=True):
        user = self.find_user(username=username)
        if user:
            logger.debug(f"User with username {username} already exists.")
            if user.roles != role:
                logger.debug(f"User with username {username} was updated.")
                user.roles = role if isinstance(role, list) else [role]
                self.update_user(user)
                return user
            return user

        user = self.user_model()
        user.first_name = first_name
        user.last_name = last_name
        user.username = username
        user.email = email
        user.active = active
        user.main_inn = main_inn
        user.head_inn = head_inn
        user.roles = role if isinstance(role, list) else [role]

        try:
            self.get_session.add(user)
            self.get_session.commit()
        except SQLAlchemyError as e:
            self.get_session.rollback()
            logger.error(f"Error adding user: {e}")
            raise

        return user


# AuthOIDCView
class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        sm = self.appbuilder.sm
        oidc = sm.oid

        @sm.oid.require_login
        def handle_login():
            try:
                info = oidc.user_getinfo([
                    'preferred_username', 'given_name', 'family_name', 'email',
                    'roles', 'inn', 'headINNName'
                ])
                user = self.create_or_update_user(info, sm)
                if user and user.is_active:
                    login_user(user, remember=False)
                    return redirect(self.appbuilder.get_url_for_index)
                else:
                    logger.error('Your account is not active')
                    return redirect('/login/')
            except Exception as e:
                logger.error(f'OIDC login failed: {e}')
                flash('Authentication failed', 'danger')
                return redirect('/login/')

        return handle_login()

    def create_or_update_user(self, info, sm):
        # Query roles from Superset and filter based on OIDC roles
        superset_roles = sm.get_all_roles()
        user_roles = [role for role in superset_roles if
                      role.name in info.get('roles', [])]

        # If no roles are found, assign a default role
        if not user_roles:
            default_role = sm.find_role(sm.auth_user_registration_role)
            user_roles = [default_role] if default_role else []

        # Create or update the user with the roles
        user = sm.add_user(
            username=info.get('preferred_username'),
            first_name=info.get('given_name'),
            last_name=info.get('family_name'),
            email=info.get('email').lower(),  # Normalize email
            role=user_roles,
            main_inn=info.get('inn'),
            head_inn=info.get('headINNName')
        )
        return user

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        logout_user()
        oidc = self.appbuilder.sm.oid
        oidc.logout()
        redirect_url = 'http://158.160.81.201:8000/'
        issuer = oidc.client_secrets.get('issuer')
        if issuer:
            return redirect(redirect_url)
            # f"{issuer}/protocol/openid-connect/logout?redirect_uri={quote(
            # redirect_url)}")
        flash('Failed to log out', 'warning')
        return redirect('/')
