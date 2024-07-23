from flask import Blueprint, render_template
from flask_login import current_user
from models import Video

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    if current_user.is_authenticated:
        videos = Video.query.order_by(Video.upload_date.desc()).all()
    else:
        videos = []
    return render_template('index.html', videos=videos)