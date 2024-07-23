from flask_login import UserMixin
from app import db
from datetime import datetime
import os
from config import Config

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
        old_path = os.path.join(Config.UPLOAD_FOLDER, self.filename)
        new_path = os.path.join(Config.UPLOAD_FOLDER, new_filename)
        try:
            os.rename(old_path, new_path)
            self.filename = new_filename
        except OSError as e:
            print(f"Error renaming file: {e}")

    def __repr__(self):
        return f'<Video {self.filename}>'