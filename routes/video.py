from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import app
from utils import role_required, allowed_file
from models import Video
from app import db
from config import Config
import os

bp = Blueprint('video', __name__)

@bp.route('/upload', methods=['GET', 'POST'])
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
            file_path = os.path.join(app.Config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            new_video = Video(filename=filename, user_id=current_user.id)
            db.session.add(new_video)
            db.session.commit()
            
            flash('Video uploaded successfully', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid file type. Allowed types are: mp4, avi, mov, wmv', 'error')
            return render_template('upload.html')

@bp.route('/rename_video', methods=['POST'])
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

@bp.route('/publish')
@login_required
@role_required('Manager')
def publish():
    return render_template('publish.html')