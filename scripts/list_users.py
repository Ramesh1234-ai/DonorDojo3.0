import os, sys
<<<<<<< HEAD

=======
>>>>>>> 297b8874e9caae5b08920afe6a54ec210592d66c
# ensure Backend directory is on sys.path so "from app import app" works
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from database import db, User

with app.app_context():
    users = User.query.with_entities(User.id, User.name, User.email).all()
    for u in users:
        print(u)