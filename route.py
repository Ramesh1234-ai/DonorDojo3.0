from flask import Blueprint, request, jsonify
from Backend.models import db, User, DonorProfile
from flask_login import login_user, logout_user, login_required, current_user

api = Blueprint("api", __name__)

@api.route("/register", methods=["POST"])
def register():
    data = request.json
    new_user = User(email=data["email"], password=data["password"])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User registered"})

@api.route("/profile", methods=["POST"])
@login_required
def update_profile():
    data = request.json
    profile = DonorProfile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        profile = DonorProfile(user_id=current_user.id)
        db.session.add(profile)
    profile.name = data["name"]
    profile.age = data["age"]
    profile.blood_group = data["blood_group"]
    profile.phone = data["phone"]
    profile.location = data["location"]
    profile.availability = data.get("availability", True)
    db.session.commit()
    return jsonify({"msg": "Profile updated"})

@api.route("/donors", methods=["GET"])
def get_donors():
    donors = DonorProfile.query.all()
    return jsonify([{
        "name": d.name,
        "blood_group": d.blood_group,
        "location": d.location,
        "availability": d.availability
    } for d in donors])
