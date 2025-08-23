from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os, uuid, datetime, json, ssl, smtplib, jwt
from email.message import EmailMessage
from jinja2 import TemplateNotFound
from database import db, User, Donor, BloodRequest, Donation, ContactMessage, Notification

# -------------------------
# Flask App Setup
# -------------------------
app = Flask(
    __name__,
    template_folder='../Frontend/templates',
    static_folder='../Frontend/static'
)
CORS(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:root@localhost:3306/login_db"
db.init_app(app)

# create tables if not exist
with app.app_context():
    db.create_all()

# -------------------------
# Utility: Notifications
# -------------------------
def send_notification(user, message):
    try:
        notif = Notification(
            id=str(uuid.uuid4()),
            user_id=user.id,
            message=message
        )
        db.session.add(notif)
        db.session.commit()

        print(f"[NOTIFICATION] To: {user.email} - {message}")

        EMAIL_USER = os.environ.get('EMAIL_USER')
        EMAIL_PASS = os.environ.get('EMAIL_PASS')
        if EMAIL_USER and EMAIL_PASS:
            msg = EmailMessage()
            msg['Subject'] = "Blood.Ninja Notification"
            msg['From'] = EMAIL_USER
            msg['To'] = user.email
            msg.set_content(message)

            context = ssl.create_default_context()
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(EMAIL_USER, EMAIL_PASS)
                smtp.send_message(msg)

    except Exception as e:
        print("❌ Notification failed:", e)

# -------------------------
# Auth Decorator
# -------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# -------------------------
# Routes
# -------------------------

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400

    try:
        new_user = User(
            id=str(uuid.uuid4()),
            name=data['name'],
            email=data['email'],
            password=generate_password_hash(data['password']),
            role=data.get('role', 'user'),
            created_at=datetime.datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.flush()

        if new_user.role == 'donor':
            donor = Donor(
                id=str(uuid.uuid4()),
                user_id=new_user.id,
                blood_type=data.get('blood_type'),
                is_available=True
            )
            db.session.add(donor)

        db.session.commit()
        send_notification(new_user, f"Welcome {new_user.name}! You are registered as {new_user.role}.")

        return jsonify({'message': 'User registered', 'user': {
            'id': new_user.id, 'email': new_user.email, 'name': new_user.name, 'role': new_user.role
        }}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Registration failed: {e}'}), 500


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing credentials'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid email or password'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'])

    send_notification(user, f"Hello {user.name}, you just logged in successfully.")

    return jsonify({'token': token, 'user': {'id': user.id, 'name': user.name, 'email': user.email}}), 200


@app.route('/api/donations', methods=['POST'])
@token_required
def create_donation(current_user):
    if current_user.role != 'donor':
        return jsonify({'message': 'Not authorized'}), 403

    data = request.get_json()
    new_donation = Donation(
        id=str(uuid.uuid4()),
        donor_id=current_user.id,
        donation_date=datetime.datetime.now(),
        blood_type=data['blood_type'],
        quantity=data['quantity'],
        location=data['location'],
        notes=data.get('notes', '')
    )
    donor = Donor.query.filter_by(user_id=current_user.id).first()
    if donor:
        donor.last_donation_date = datetime.datetime.now()

    db.session.add(new_donation)
    db.session.commit()

    send_notification(current_user, f"Thanks {current_user.name}! Your donation of {new_donation.quantity}ml {new_donation.blood_type} has been recorded.")

    return jsonify({'message': 'Donation recorded'}), 201


@app.route('/api/blood-requests', methods=['POST'])
@token_required
def create_blood_request(current_user):
    data = request.get_json()
    new_request = BloodRequest(
        id=str(uuid.uuid4()),
        requester_id=current_user.id,
        blood_type=data['blood_type'],
        quantity=data['quantity'],
        urgency=data['urgency'],
        hospital=data['hospital'],
        contact_number=data['contact_number'],
        notes=data.get('notes', ''),
        request_date=datetime.datetime.now(),
        status='pending'
    )
    db.session.add(new_request)
    db.session.commit()

    send_notification(current_user, f"Your request for {new_request.quantity} units of {new_request.blood_type} has been submitted.")

    return jsonify({'message': 'Blood request created'}), 201


@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    notifs = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return jsonify([{'id': n.id, 'message': n.message, 'created_at': n.created_at.isoformat()} for n in notifs]), 200


@app.route('/api/contact', methods=['POST'])
def submit_contact():
    data = request.get_json() or {}
    if not data.get('name') or not data.get('email') or not data.get('message'):
        return jsonify({'message': 'Name, email, and message required'}), 400

    msg = ContactMessage(
        id=str(uuid.uuid4()),
        name=data['name'],
        email=data['email'],
        phone=data.get('phone'),
        subject=data.get('subject'),
        message=data['message'],
        created_at=datetime.datetime.utcnow()
    )
    db.session.add(msg)
    db.session.commit()
    return jsonify({'message': 'Contact message saved'}), 201

# -------------------------
# Frontend Pages
# -------------------------
@app.route('/')
def home(): return render_template('index.html')

@app.route('/<path:name>.html')
def html_alias(name):
    try: return render_template(f'{name}.html')
    except TemplateNotFound: return ("Not Found", 404)

@app.route('/dashboard')
def dashboard_page(): return render_template('dashboard.html')

@app.route('/about')
def about_page(): return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
