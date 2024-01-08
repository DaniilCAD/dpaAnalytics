from flask_login import current_user


def get_current_user_main_inn():
    return current_user.main_inn


def get_current_user_head_inn():
    return current_user.head_inn

