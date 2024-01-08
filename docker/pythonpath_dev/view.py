from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user, logout_user
from flask import redirect, flash
from flask_appbuilder import expose
import logging

logger = logging.getLogger()


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
                    'roles', 'inn', 'accessLevelINN'
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
            head_inn=info.get('accessLevelINN')
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
        flash('Failed to log out', 'warning')
        return redirect('/')
