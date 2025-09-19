# test_app.py  — minimal reproducible server
from flask import Flask, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
# allow all origins and allow preflight methods
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

@app.route('/api/inventory', methods=['GET', 'OPTIONS'])
def get_inventory():
    sample = [
        {"blood_group": "A+", "units": 10},
        {"blood_group": "B+", "units": 8},
        {"blood_group": "O-", "units": 5},
    ]
    return jsonify(sample)

if __name__ == '__main__':
    print("🚀 Starting minimal test_app.py")
    print("✅ Available routes:")
    for rule in app.url_map.iter_rules():
        print("   ", rule)
    app.run(debug=True, host='0.0.0.0', port=5000)
