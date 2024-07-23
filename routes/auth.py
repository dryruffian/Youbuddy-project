from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models import User
from app import db, oauth
from session_manager import update_login_time, remove_user_session

bp = Blueprint('auth', __name__)

@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('auth.signup'))
        new_user = User(email=email, name=name, password=generate_password_hash(password, method='pbkdf2:sha256'), role='Editor')
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('auth.login'))
    return render_template('signup.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            update_login_time(user.id)
            access_token = create_access_token(identity=user.id)
            return render_template('index.html'), 200
        else:
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))
    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    remove_user_session(user_id)
    return redirect(url_for('main.index'))

@bp.route('/login/google')
def google_login():
    redirect_uri = url_for('auth.google_authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@bp.route('/authorize/google')
def google_authorize():
    try:
        token = oauth.google.authorize_access_token()
        resp = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()
        user = User.query.filter_by(email=user_info['email']).first()
        if not user:
            user = User(email=user_info['email'], name=user_info['name'], role='Editor')
            db.session.add(user)
            db.session.commit()
        login_user(user)
        update_login_time(user.id)
        return redirect(url_for('main.index'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}')
        return redirect(url_for('main.index'))
