from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Donor(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    blood_type = db.Column(db.String(10))
    last_donation_date = db.Column(db.DateTime)
    medical_conditions = db.Column(db.Text)
    is_available = db.Column(db.Boolean, default=True)

class BloodRequest(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    requester_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    blood_type = db.Column(db.String(10), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    urgency = db.Column(db.String(20), nullable=False)
    hospital = db.Column(db.String(200), nullable=False)
    contact_number = db.Column(db.String(20), nullable=False)
    notes = db.Column(db.Text)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')

class Donation(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    donor_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    donation_date = db.Column(db.DateTime, nullable=False)
    blood_type = db.Column(db.String(10), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    notes = db.Column(db.Text)

class ContactMessage(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(50))
    subject = db.Column(db.String(200))
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):   # ✅ Now outside, at the same level as other models
    __tablename__ = 'notification'

    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # relationship to User (optional)
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

    def __repr__(self):
        return f"<Notification {self.id} - {self.user_id}>"




