# app.py

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv

load_dotenv() 

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    role = db.Column(db.String(20))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash('You do not have permission to access this page.')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    try:
        token = google.authorize_access_token()
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()
        user = User.query.filter_by(email=user_info['email']).first()
        if not user:
            user = User(email=user_info['email'], name=user_info['name'], role='Editor')
            db.session.add(user)
            db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}')
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/update_role', methods=['POST'])
@login_required

@role_required('Editor')
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

@app.route('/upload')
@login_required
@role_required('Editor')
def upload():
    return render_template('upload.html')

@app.route('/publish')
@login_required
@role_required('Manager')
def publish():
    return render_template('publish.html')

@app.route('/admin')
@login_required
@role_required('Editor')
def admin():
    return render_template('admin.html')

def init_db():
    with app.app_context():
        db.create_all()
        print("Database initialized.")

if __name__ == '__main__':
    if not os.path.exists('users.db'):
        init_db()
    app.run(debug=True)