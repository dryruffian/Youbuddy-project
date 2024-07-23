from datetime import datetime

logged_in_users = {}

def update_login_time(user_id):
    logged_in_users[user_id] = datetime.now()

def remove_user_session(user_id):
    logged_in_users.pop(user_id, None)

def get_logged_in_users():
    return logged_in_users