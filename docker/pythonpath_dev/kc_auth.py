from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from sqlalchemy.exc import SQLAlchemyError
from model import CustomUser
from view import AuthOIDCView
import logging

logger = logging.getLogger()


class OIDCSecurityManager(SupersetSecurityManager):
    user_model = CustomUser

    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
        self.authoidview = AuthOIDCView

    def add_user(self, username, first_name, last_name, email, role, password='',
                 main_inn='Отсутствует', head_inn='Отсутствует', active=True):
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
