from flask_appbuilder.security.sqla.models import User
from sqlalchemy import Column, String


class CustomUser(User):
    __tablename__ = 'ab_user'
    main_inn = Column(String(64))
    head_inn = Column(String(64))
