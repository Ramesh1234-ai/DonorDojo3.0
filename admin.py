from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import csv
from functools import wraps
import os
from flask import Flask, render_template

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../Frontend/templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../Frontend/static')
print("Template files:", os.listdir(template_dir))
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

#----------------------------
@app.route('/')
def index_page():
     return render_template('adminPanel.html')
# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bdms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-change-this-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

@app.before_first_request
def setup():
    print("App is starting up...")

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='donor')  # admin, donor, recipient
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    donor_profile = db.relationship('Donor', backref='user', uselist=False)
    recipient_profile = db.relationship('Recipient', backref='user', uselist=False)

class Donor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    blood_group = db.Column(db.String(5), nullable=False)  # A+, A-, B+, B-, AB+, AB-, O+, O-
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    last_donation_date = db.Column(db.Date)
    next_eligible_date = db.Column(db.Date)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    donations = db.relationship('DonationRequest', foreign_keys='DonationRequest.donor_id', backref='assigned_donor')

class Recipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    blood_group = db.Column(db.String(5), nullable=False)
    required_units = db.Column(db.Integer, nullable=False, default=1)
    urgency = db.Column(db.String(10), nullable=False, default='medium')  # high, medium, low
    hospital_name = db.Column(db.String(100), nullable=False)
    hospital_address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    medical_condition = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    requests = db.relationship('DonationRequest', foreign_keys='DonationRequest.recipient_id', backref='recipient')

class DonationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('recipient.id'), nullable=False)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, matched, fulfilled, cancelled
    requested_date = db.Column(db.DateTime, default=datetime.utcnow)
    fulfilled_date = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Blood compatibility matrix
BLOOD_COMPATIBILITY = {
    'O-': ['O-', 'O+', 'A-', 'A+', 'B-', 'B+', 'AB-', 'AB+'],
    'O+': ['O+', 'A+', 'B+', 'AB+'],
    'A-': ['A-', 'A+', 'AB-', 'AB+'],
    'A+': ['A+', 'AB+'],
    'B-': ['B-', 'B+', 'AB-', 'AB+'],
    'B+': ['B+', 'AB+'],
    'AB-': ['AB-', 'AB+'],
    'AB+': ['AB+']
}
# Helper Functions
def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            if not user or user.role not in required_roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def calculate_next_eligible_date(last_donation_date):
    if last_donation_date:
        return last_donation_date + timedelta(days=90)  # 3 months gap
    return datetime.now().date()

def find_compatible_donors(blood_group, city, state):
    # Find donors who can donate to this blood group
    compatible_donors = []
    for donor_bg, can_donate_to in BLOOD_COMPATIBILITY.items():
        if blood_group in can_donate_to:
            # Find eligible donors
            today = datetime.now().date()
            donors = Donor.query.filter(
                Donor.blood_group == donor_bg,
                Donor.city == city,
                Donor.is_active == True,
                db.or_(
                    Donor.next_eligible_date == None,
                    Donor.next_eligible_date <= today
                )
            ).all()
            compatible_donors.extend(donors)
    
    return compatible_donors

# Routes
@app.route('/')
def index():
    return send_from_directory('.', 'bdms.html')

# Authentication Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'email', 'password', 'role']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400
    
    # Check if user exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    # Create user
    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=generate_password_hash(data['password']),
        role=data['role']
    )
    
    db.session.add(user)
    db.session.commit()
    
    # Create access token
    access_token = create_access_token(identity=user.id)
    
    return jsonify({
        'message': 'User registered successfully',
        'access_token': access_token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        }
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

# Donor Routes
@app.route('/api/donors', methods=['GET'])
@role_required(['admin', 'donor'])
def get_donors():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    blood_group = request.args.get('blood_group')
    city = request.args.get('city')
    
    query = Donor.query.filter_by(is_active=True)
    
    if blood_group:
        query = query.filter_by(blood_group=blood_group)
    if city:
        query = query.filter_by(city=city)
    
    donors = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'donors': [{
            'id': donor.id,
            'name': donor.name,
            'email': donor.user.email,
            'phone': donor.phone,
            'blood_group': donor.blood_group,
            'age': donor.age,
            'gender': donor.gender,
            'city': donor.city,
            'state': donor.state,
            'last_donation_date': donor.last_donation_date.isoformat() if donor.last_donation_date else None,
            'next_eligible_date': donor.next_eligible_date.isoformat() if donor.next_eligible_date else None,
            'is_eligible': donor.next_eligible_date <= datetime.now().date() if donor.next_eligible_date else True,
            'created_at': donor.created_at.isoformat()
        } for donor in donors.items],
        'total': donors.total,
        'pages': donors.pages,
        'current_page': page
    })

@app.route('/api/donors', methods=['POST'])
@role_required(['admin', 'donor'])
def create_donor():
    data = request.get_json()
    current_user_id = get_jwt_identity()
    
    # Validate required fields
    required_fields = ['name', 'phone', 'blood_group', 'age', 'gender', 'address', 'city', 'state']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400
    
    # Check if donor profile already exists for this user
    existing_donor = Donor.query.filter_by(user_id=current_user_id).first()
    if existing_donor:
        return jsonify({'error': 'Donor profile already exists'}), 400
    
    # Create donor
    last_donation = None
    if data.get('last_donation_date'):
        last_donation = datetime.strptime(data['last_donation_date'], '%Y-%m-%d').date()
    
    donor = Donor(
        user_id=current_user_id,
        name=data['name'],
        phone=data['phone'],
        blood_group=data['blood_group'],
        age=data['age'],
        gender=data['gender'],
        address=data['address'],
        city=data['city'],
        state=data['state'],
        last_donation_date=last_donation,
        next_eligible_date=calculate_next_eligible_date(last_donation)
    )
    
    db.session.add(donor)
    db.session.commit()
    
    return jsonify({
        'message': 'Donor profile created successfully',
        'donor': {
            'id': donor.id,
            'name': donor.name,
            'blood_group': donor.blood_group,
            'city': donor.city,
            'state': donor.state
        }
    }), 201

@app.route('/api/donors/<int:donor_id>', methods=['PUT'])
@role_required(['admin', 'donor'])
def update_donor(donor_id):
    donor = Donor.query.get_or_404(donor_id)
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    # Check permissions
    if current_user.role != 'admin' and donor.user_id != current_user_id:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    data = request.get_json()
    
    # Update fields
    if 'name' in data:
        donor.name = data['name']
    if 'phone' in data:
        donor.phone = data['phone']
    if 'blood_group' in data:
        donor.blood_group = data['blood_group']
    if 'age' in data:
        donor.age = data['age']
    if 'gender' in data:
        donor.gender = data['gender']
    if 'address' in data:
        donor.address = data['address']
    if 'city' in data:
        donor.city = data['city']
    if 'state' in data:
        donor.state = data['state']
    if 'last_donation_date' in data:
        last_donation = datetime.strptime(data['last_donation_date'], '%Y-%m-%d').date()
        donor.last_donation_date = last_donation
        donor.next_eligible_date = calculate_next_eligible_date(last_donation)
    
    db.session.commit()
    
    return jsonify({'message': 'Donor updated successfully'})

# Recipient Routes
@app.route('/api/recipients', methods=['GET'])
@role_required(['admin', 'recipient'])
def get_recipients():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    recipients = Recipient.query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'recipients': [{
            'id': recipient.id,
            'name': recipient.name,
            'email': recipient.user.email,
            'phone': recipient.phone,
            'blood_group': recipient.blood_group,
            'required_units': recipient.required_units,
            'urgency': recipient.urgency,
            'hospital_name': recipient.hospital_name,
            'city': recipient.city,
            'state': recipient.state,
            'medical_condition': recipient.medical_condition,
            'created_at': recipient.created_at.isoformat()
        } for recipient in recipients.items],
        'total': recipients.total,
        'pages': recipients.pages,
        'current_page': page
    })

@app.route('/api/recipients', methods=['POST'])
@role_required(['admin', 'recipient'])
def create_recipient():
    data = request.get_json()
    current_user_id = get_jwt_identity()
    
    required_fields = ['name', 'phone', 'blood_group', 'required_units', 'urgency', 'hospital_name', 'hospital_address', 'city', 'state']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400
    
    recipient = Recipient(
        user_id=current_user_id,
        name=data['name'],
        phone=data['phone'],
        blood_group=data['blood_group'],
        required_units=data['required_units'],
        urgency=data['urgency'],
        hospital_name=data['hospital_name'],
        hospital_address=data['hospital_address'],
        city=data['city'],
        state=data['state'],
        medical_condition=data.get('medical_condition', '')
    )
    
    db.session.add(recipient)
    db.session.commit()
    
    # Create a donation request
    donation_request = DonationRequest(
        recipient_id=recipient.id,
        status='pending'
    )
    db.session.add(donation_request)
    db.session.commit()
    
    return jsonify({
        'message': 'Recipient profile and donation request created successfully',
        'recipient': {
            'id': recipient.id,
            'name': recipient.name,
            'blood_group': recipient.blood_group,
            'urgency': recipient.urgency
        }
    }), 201

# Donation Request Routes
@app.route('/api/requests', methods=['GET'])
@role_required(['admin'])
def get_donation_requests():
    requests = DonationRequest.query.all()
    
    return jsonify({
        'requests': [{
            'id': req.id,
            'recipient': {
                'id': req.recipient.id,
                'name': req.recipient.name,
                'blood_group': req.recipient.blood_group,
                'required_units': req.recipient.required_units,
                'urgency': req.recipient.urgency,
                'hospital_name': req.recipient.hospital_name,
                'city': req.recipient.city,
                'state': req.recipient.state
            },
            'donor': {
                'id': req.assigned_donor.id,
                'name': req.assigned_donor.name,
                'blood_group': req.assigned_donor.blood_group,
                'city': req.assigned_donor.city
            } if req.assigned_donor else None,
            'status': req.status,
            'requested_date': req.requested_date.isoformat(),
            'fulfilled_date': req.fulfilled_date.isoformat() if req.fulfilled_date else None,
            'notes': req.notes
        } for req in requests]
    })

@app.route('/api/requests/<int:request_id>/match', methods=['POST'])
@role_required(['admin'])
def match_donor_to_request(request_id):
    donation_request = DonationRequest.query.get_or_404(request_id)
    
    if donation_request.status != 'pending':
        return jsonify({'error': 'Request is not pending'}), 400
    
    # Find compatible donors
    compatible_donors = find_compatible_donors(
        donation_request.recipient.blood_group,
        donation_request.recipient.city,
        donation_request.recipient.state
    )
    
    if not compatible_donors:
        return jsonify({'error': 'No compatible donors found'}), 404
    
    return jsonify({
        'compatible_donors': [{
            'id': donor.id,
            'name': donor.name,
            'blood_group': donor.blood_group,
            'city': donor.city,
            'phone': donor.phone,
            'last_donation_date': donor.last_donation_date.isoformat() if donor.last_donation_date else None,
            'next_eligible_date': donor.next_eligible_date.isoformat() if donor.next_eligible_date else None
        } for donor in compatible_donors]
    })

@app.route('/api/requests/<int:request_id>/assign', methods=['PUT'])
@role_required(['admin'])
def assign_donor_to_request(request_id):
    data = request.get_json()
    donor_id = data.get('donor_id')
    
    if not donor_id:
        return jsonify({'error': 'donor_id is required'}), 400
    
    donation_request = DonationRequest.query.get_or_404(request_id)
    donor = Donor.query.get_or_404(donor_id)
    
    donation_request.donor_id = donor_id
    donation_request.status = 'matched'
    
    db.session.commit()
    
    return jsonify({'message': 'Donor assigned successfully'})

@app.route('/api/requests/<int:request_id>/fulfill', methods=['PUT'])
@role_required(['admin'])
def fulfill_request(request_id):
    donation_request = DonationRequest.query.get_or_404(request_id)
    
    if donation_request.status != 'matched':
        return jsonify({'error': 'Request must be matched before fulfilling'}), 400
    
    donation_request.status = 'fulfilled'
    donation_request.fulfilled_date = datetime.utcnow()
    
    # Update donor's last donation date
    if donation_request.assigned_donor:
        today = datetime.now().date()
        donation_request.assigned_donor.last_donation_date = today
        donation_request.assigned_donor.next_eligible_date = calculate_next_eligible_date(today)
    
    db.session.commit()
    
    return jsonify({'message': 'Request fulfilled successfully'})

# Dashboard & Statistics
@app.route('/api/dashboard/stats', methods=['GET'])
@role_required(['admin'])
def get_dashboard_stats():
    today = datetime.now().date()
    
    # Total counts
    total_donors = Donor.query.filter_by(is_active=True).count()
    total_recipients = Recipient.query.count()
    
    # Eligible donors (can donate today)
    eligible_donors = Donor.query.filter(
        Donor.is_active == True,
        db.or_(
            Donor.next_eligible_date == None,
            Donor.next_eligible_date <= today
        )
    ).count()
    
    # Request statistics
    pending_requests = DonationRequest.query.filter_by(status='pending').count()
    matched_requests = DonationRequest.query.filter_by(status='matched').count()
    fulfilled_requests = DonationRequest.query.filter_by(status='fulfilled').count()
    
    # Blood group distribution
    blood_groups = db.session.query(Donor.blood_group, db.func.count(Donor.id)).group_by(Donor.blood_group).all()
    
    return jsonify({
        'total_donors': total_donors,
        'total_recipients': total_recipients,
        'eligible_donors': eligible_donors,
        'active_donors': eligible_donors,
        'pending_requests': pending_requests,
        'matched_requests': matched_requests,
        'fulfilled_requests': fulfilled_requests,
        'blood_group_distribution': [{'blood_group': bg, 'count': count} for bg, count in blood_groups]
    })

# Export Routes
@app.route('/api/export/donors', methods=['GET'])
@role_required(['admin'])
def export_donors():
    donors = Donor.query.filter_by(is_active=True).all()
    
    export_data = {
        'export_date': datetime.now().isoformat(),
        'total_donors': len(donors),
        'donors': [{
            'id': donor.id,
            'name': donor.name,
            'email': donor.user.email,
            'phone': donor.phone,
            'blood_group': donor.blood_group,
            'age': donor.age,
            'gender': donor.gender,
            'address': donor.address,
            'city': donor.city,
            'state': donor.state,
            'last_donation_date': donor.last_donation_date.isoformat() if donor.last_donation_date else None,
            'next_eligible_date': donor.next_eligible_date.isoformat() if donor.next_eligible_date else None,
            'created_at': donor.created_at.isoformat()
        } for donor in donors]
    }
    
    return jsonify(export_data)

@app.route('/api/export/requests', methods=['GET'])
@role_required(['admin'])
def export_requests():
    requests = DonationRequest.query.all()
    
    export_data = {
        'export_date': datetime.now().isoformat(),
        'total_requests': len(requests),
        'requests': [{
            'id': req.id,
            'recipient_name': req.recipient.name,
            'recipient_blood_group': req.recipient.blood_group,
            'required_units': req.recipient.required_units,
            'urgency': req.recipient.urgency,
            'hospital_name': req.recipient.hospital_name,
            'city': req.recipient.city,
            'state': req.recipient.state,
            'donor_name': req.assigned_donor.name if req.assigned_donor else None,
            'donor_blood_group': req.assigned_donor.blood_group if req.assigned_donor else None,
            'status': req.status,
            'requested_date': req.requested_date.isoformat(),
            'fulfilled_date': req.fulfilled_date.isoformat() if req.fulfilled_date else None
        } for req in requests]
    }
    
    return jsonify(export_data)

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()
    
    # Create admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@bdms.com',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@bdms.com',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created: username='admin', password='admin123'")
    app.run(debug=True, port=5000)