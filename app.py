import os, uuid, datetime, ssl, smtplib
from flask import Flask, request, jsonify, render_template,session, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
from email.message import EmailMessage
from firebase_admin import auth, credentials, initialize_app
import jwt
from database import db, User, Donor, BloodRequest, Donation, ContactMessage, Notification
import hashlib
import base64
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
from flask_session import Session
from datetime import timedelta

# ------------------------- #
# Load Environment Variables
# ------------------------- #
load_dotenv()
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")

# Firebase Admin SDK
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
cred_path = os.path.join(BASE_DIR, "firebase_config.json")

print("Looking for Firebase config at:", cred_path)
cred = credentials.Certificate(cred_path)
initialize_app(cred)

# ------------------------- #
# Flask Setup
# ------------------------- #
app = Flask(
    __name__,
    template_folder='../Frontend/templates',
    static_folder='../Frontend/static'
)

# ✅ Use a consistent secret key (NOT random each time)
SECRET_KEY = os.environ.get("SECRET_KEY", "dev_secret_key")  # change for production
app.secret_key = SECRET_KEY
app.config["SECRET_KEY"] = SECRET_KEY

# ✅ Proper session configuration
app.config["SESSION_TYPE"] = "filesystem"  # store sessions on disk
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=1)

# ✅ Critical for cookies to work in modern browsers
app.config["SESSION_COOKIE_SAMESITE"] = "None"  # allow cross-site usage
app.config["SESSION_COOKIE_SECURE"] = False     # set to True if using HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True    # prevents JS from stealing cookie

# ✅ CORS must allow credentials & correct origin
CORS(app, supports_credentials=True, origins=[
    "http://10.162.33.221:5500",  # your frontend (adjust port if needed)
    "http://localhost:5500"
])

# ✅ Initialize server-side session
Session(app)

db.init_app(app)
with app.app_context():
    db.create_all()

# ------------------------- #
# Utility: Notifications
# ------------------------- #
def send_notification(user, message):
    try:
        notif = Notification(id=str(uuid.uuid4()), user_id=user.id, message=message)
        db.session.add(notif)
        db.session.commit()

        # Send Email
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

# ------------------------- #
# Auth Decorator
# ------------------------- #
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', None)
        if token:
            token = token.split(" ")[1]
        if not token:
            return jsonify({'message': 'Token missing'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# ------------------------- #
# Auth Routes
# ------------------------- #
@app.route('/api/auth/register', methods=['POST'])
def register():
    username = request.form.get("username")
    avatar = request.form.get("avatar") or "default.png"

    # 🚨 normally you'd insert into DB / Firebase here
    user = {"username": username, "avatar": avatar}

    # ✅ Save in session
    session["user"] = user
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
            donor = Donor(id=str(uuid.uuid4()), user_id=new_user.id, blood_type=data.get('blood_type'), is_available=True)
            db.session.add(donor)

        db.session.commit()
        send_notification(new_user, f"Welcome {new_user.name}! You are registered as {new_user.role}.")
        return jsonify({'message': 'User registered', 'user': {'id': new_user.id, 'email': new_user.email, 'name': new_user.name, 'role': new_user.role}}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Registration failed: {e}'}), 500
#------------------------- #
# Login Route
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json
    try:
        if "idToken" in data:  # Google login
            decoded_token = auth.verify_id_token(data["idToken"])
            email = decoded_token["email"]
            name = decoded_token.get("name", email.split("@")[0])
            avatar_url = decoded_token.get("picture", "/static/default-avatar.png")
            role = "admin" if email.endswith("@admin.com") else "user"

        elif "email" in data and "password" in data:  # ✅ Manual login
            email = data["email"]
            password = data["password"]

            # ✅ Replace with real DB lookup:
            # user = db.query(User).filter_by(email=email).first()
            # if not user or not check_password_hash(user.password, password): ...
            if email == "test@admin.com" and password == "1234":
                name = "Test Admin"
                role = "admin"
                avatar_url = "/static/default-avatar.png"
            else:
                return jsonify({"error": "Invalid credentials"}), 401

        else:
            return jsonify({"error": "Invalid login data"}), 400

        # ✅ Save to session
        session.permanent = True
        session["user"] = {
            "name": name,
            "email": email,
            "avatar": avatar_url,
            "role": role
        }

        return jsonify({"message": "Login successful", "user": session["user"]})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
#------------------------- #
# Firebase Login Route
@app.route('/api/auth/firebase-login', methods=['POST'])
def firebase_login():
    """
    Frontend sends: { idToken: <Firebase ID Token> }
    """
    data = request.get_json()
    id_token = data.get('idToken')
    if not id_token:
        return jsonify({'message': 'Missing Firebase token'}), 400

    try:
        # 1. Verify token
        decoded_token = auth.verify_id_token(id_token)
        email = decoded_token['email']
        name = decoded_token.get('name', email.split("@")[0])

        # 2. Fetch or create user in DB
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                id=str(uuid.uuid4()),
                name=name,
                email=email,

                role='user',
                password=""   # because Firebase manages auth
            )
            db.session.add(user)
            db.session.commit()

        # 3. Store in session (now user is defined ✅)
        avatar_url = getattr(user, "avatar_url", None) or generate_avatar(user.name)
        session["user"] = {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "avatar": avatar_url
        }

        # 4. Send notification
        send_notification(user, f"Hello {user.name}, you just logged in via Firebase successfully!")

        # 5. Generate JWT token for frontend
        token = jwt.encode({
            'user_id': user.id,
            'email': user.email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, SECRET_KEY)

        return jsonify({
            'success': True,
            'method': 'firebase',
            'token': token,
            'user': session["user"]
        })

    except Exception as e:
        return jsonify({'success': False, 'message': f'Firebase login failed: {e}'}), 400
# ------------------------- #
# Donations & Blood Requests
# ------------------------- #
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

# ------------------------- #
# Frontend Pages
# ------------------------- #
@app.route('/')
def home(): return render_template('index.html')

@app.route('/<path:name>.html')
def html_alias(name):
    try:
        return render_template(f'{name}.html')
    except:
        return ("Not Found", 404)

@app.route('/dashboard')
def dashboard_page(): return render_template('index.html')

@app.route('/about')
def about_page(): return render_template('about.html')

@app.route("/recipient")
def recipient():
    try:
        if "user" not in session:
            return jsonify({"error": "User not logged in"}), 401

        user = session.get("user", {})
        return render_template(
            "Recipent.html",
            user=user,
            avatar_url=user.get("avatar", "/static/default-avatar.png")
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# ------------------------- #
@app.route("/api/auth/status")
def auth_status():
    if "user" in session:
        return jsonify({
            "logged_in": True,
            "user": session["user"]
        })
    else:
        return jsonify({"logged_in": False}), 401
# ------------------------- #
@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()  # ✅ clears the whole session safely
    return jsonify({"message": "Logged out"}), 200

# ------------------------- #
#------------------------- #
@app.route('/verify_token', methods=['POST'])
def verify_token():
    data = request.get_json()
    token = data.get("token")

    try:
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']
        email = decoded_token.get('email')
        return jsonify({"status": "success", "uid": uid, "email": email})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 401

# ------------------------- #
# Avatar Generation
# ------------------------- #
inventory = [
    {"blood_group": "A+", "units": 10},
    {"blood_group": "B+", "units": 8},
    {"blood_group": "O+", "units": 15},
    {"blood_group": "AB+", "units": 5},
]

@app.route('/api/inventory', methods=['GET'])
def get_inventory():
    return jsonify(inventory)

@app.route("/api/protected")
def protected():
    if "user" not in session:
        return jsonify({"error": "User not logged in"}), 401
    return jsonify({"message": f"Welcome {session['user']}"})

@app.route("/api/admin/dashboard")
def admin_dashboard():
    user = session.get("user")
    if not user:
        return jsonify({"error": "Not logged in"}), 401
    if user["role"] != "admin":
        return jsonify({"error": "Access denied"}), 403
    return jsonify({"message": f"Welcome Admin {user['name']}!"})

# ------------------------- #
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
