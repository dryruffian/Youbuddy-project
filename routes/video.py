from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import app
from utils import role_required, allowed_file
from models import Video
from app import db
import os
from flask import current_app
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
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            new_video = Video(filename=filename, user_id=current_user.id)
            db.session.add(new_video)
            db.session.commit()
            
            flash('Video uploaded successfully', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid file type. Allowed types are: mp4, avi, mov, wmv', 'error')
            return redirect(url_for('video.upload'))
    
    # GET request
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


@bp.route('/delete_video', methods=['POST'])
@login_required
def delete_video():
    data = request.json
    video_id = data.get('video_id')

    if not video_id:
        return jsonify({'success': False, 'message': 'Missing video_id'}), 400

    video = Video.query.get(video_id)
    if not video:
        return jsonify({'success': False, 'message': 'Video not found'}), 404

    # Check if the user has permission to delete the video
    if video.user_id != current_user.id and current_user.role not in ['Creator', 'Manager']:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    try:
        # Delete the video file
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], video.filename)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Delete the database entry
        db.session.delete(video)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Video deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/publish/<int:video_id>')
@login_required
@role_required('Manager')
def publish(video_id):
    video = Video.query.get_or_404(video_id)
    return render_template('publish.html', video=video)

@bp.route('/publish_video', methods=['POST'])
@login_required
@role_required('Manager')
def publish_video():
    video_id = request.form.get('video_id')
    video = Video.query.get_or_404(video_id)

    video.title = request.form.get('title')
    video.description = request.form.get('description')
    video.tags = request.form.get('tags')
    video.category = request.form.get('category')
    video.is_public = 'isPublic' in request.form

    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Video published successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500