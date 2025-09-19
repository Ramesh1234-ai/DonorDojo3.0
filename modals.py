from Backend.app import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    donor_profile = db.relationship("DonorProfile", backref="user", uselist=False)

class DonorProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    name = db.Column(db.String(100))
    age = db.Column(db.Integer)
    blood_group = db.Column(db.String(5))
    phone = db.Column(db.String(15))
    location = db.Column(db.String(100))
    availability = db.Column(db.Boolean, default=True)
    last_donation_date = db.Column(db.DateTime, default=datetime.utcnow)
