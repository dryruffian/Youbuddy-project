from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from utils import role_required
from models import User
from app import db
from session_manager import get_logged_in_users,remove_user_session
from datetime import datetime, timedelta

bp = Blueprint('admin', __name__)

@bp.route('/admin')
@login_required
@role_required('Creator')
def admin():
    all_users = User.query.all()
    logged_in_users = get_logged_in_users()
    active_users = [user for user in all_users if user.id in logged_in_users]
    return render_template('admin.html', all_users=all_users, active_users=active_users)

@bp.route('/cleanup_sessions')
@login_required
@role_required('Creator')
def cleanup_sessions():
    current_time = datetime.now()
    inactive_threshold = timedelta(hours=1)  # Adjust as needed
    logged_in_users = get_logged_in_users()
    inactive_users = [user_id for user_id, login_time in logged_in_users.items() 
                      if current_time - login_time > inactive_threshold]
    for user_id in inactive_users:
        remove_user_session(user_id)
    flash(f'Removed {len(inactive_users)} inactive sessions', 'info')
    return redirect(url_for('admin.admin'))

@bp.route('/update_role', methods=['POST'])
@login_required
@role_required('Creator')
def update_role():
    user_id = request.form.get('user_id')
    new_role = request.form.get('new_role')
    user = User.query.get(user_id)
    if user:
        user.role = new_role
        db.session.commit()
        flash(f'Role updated for {user.name}', 'success')
    else:
        flash('User not found', 'error')
    return redirect(url_for('admin'))