from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
from datetime import datetime,timedelta


load_dotenv()
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'wmv'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
logged_in_users = {}
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

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('videos', lazy=True))

    def rename(self, new_filename):
        old_path = os.path.join(app.config['UPLOAD_FOLDER'], self.filename)
        new_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        os.rename(old_path, new_path)
        self.filename = new_filename

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            access_token = create_access_token(identity=user.id)
            return jsonify(access_token=access_token), 200
        else:
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('signup'))
        new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'), role='Editor')
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/protected')
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify(logged_in_as=user.email), 200


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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
    if current_user.is_authenticated:
        videos = Video.query.order_by(Video.upload_date.desc()).all()
    else:
        videos = []
    return render_template('index.html', videos=videos)



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
        logged_in_users[user.id] = datetime.now()  
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'An error occurred: {str(e)}')
        return redirect(url_for('index'))



@app.route('/update_role', methods=['POST'])
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

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@role_required('Creator')
def upload():
    if request.method == 'POST':
        if 'video' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['video']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            new_video = Video(filename=filename, user_id=current_user.id)
            db.session.add(new_video)
            db.session.commit()
            
            flash('Video uploaded successfully', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid file type. Allowed types are: mp4, avi, mov, wmv', 'error')
    return render_template('upload.html')

@app.route('/rename_video', methods=['POST'])
@login_required
def rename_video():
    data = request.json
    video_id = data.get('video_id')
    new_filename = data.get('new_filename')

    if not video_id or not new_filename:
        return jsonify({'success': False, 'message': 'Missing video_id or new_filename'}), 400

    video = Video.query.get(video_id)
    if not video:
        return jsonify({'success': False, 'message': 'Video not found'}), 404

    if video.user_id != current_user.id and current_user.role != 'Creator':
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    try:
        video.rename(new_filename)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Video renamed successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    
    
@app.route('/publish')
@login_required
@role_required('Manager')
def publish():
    return render_template('publish.html')


@app.route('/cleanup_sessions')
@login_required
@role_required('Creator')
def cleanup_sessions():
    current_time = datetime.now()
    inactive_threshold = timedelta(hours=1)  # Adjust as needed
    inactive_users = [user_id for user_id, login_time in logged_in_users.items() 
                      if current_time - login_time > inactive_threshold]
    for user_id in inactive_users:
        logged_in_users.pop(user_id, None)
    flash(f'Removed {len(inactive_users)} inactive sessions', 'info')
    return redirect(url_for('admin'))


@app.route('/admin')
@login_required
@role_required('Creator')
def admin():
    all_users = User.query.all()
    # logged_in_users = [user for user in all_users if user.id in logged_in_users]
    return render_template('admin.html', all_users=all_users)

def init_db():
    with app.app_context():
        db.create_all()
        print("Database initialized.")

if __name__ == '__main__':
    if not os.path.exists('users.db'):
        init_db()
    app.run(debug=True)