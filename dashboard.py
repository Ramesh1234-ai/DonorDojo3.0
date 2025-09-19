from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
from werkzeug.security import check_password_hash
import logging
import os



# Debugging: Check if templates folder is correctly set
app = Flask(__name__, template_folder="Frontend/templates")
print("app.root_path =", app.root_path)
print("app.template_folder =", app.template_folder)
try:
    print("templates dir exists:", os.path.isdir(app.template_folder))
    print("templates dir contents:", os.listdir(app.template_folder))
except Exception as e:
    print("Error listing templates:", e)
# End Debugging
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Change in production

# Enable CORS for all routes
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'database': os.environ.get('DB_NAME', 'login'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', 'root'),
    'port': int(os.environ.get('DB_PORT', 3306)),
    'charset': 'utf8mb4',
    'use_unicode': True,
    'autocommit': True
}

def get_db_connection():
    """Create and return a database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        logger.error(f"Database connection error: {e}")
        return None

def init_database():
    """Initialize database with required tables"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        
        # Create blood_inventory table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blood_inventory (
                id INT AUTO_INCREMENT PRIMARY KEY,
                blood_type VARCHAR(5) NOT NULL UNIQUE,
                units INT NOT NULL DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_blood_type (blood_type)
            )
        """)
        
        # Create users table for authentication
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                email VARCHAR(100) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_username (username),
                INDEX idx_email (email)
            )
        """)
        
        # Create donors table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS donors (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE,
                phone VARCHAR(15),
                blood_type VARCHAR(5) NOT NULL,
                age INT,
                last_donation_date DATE,
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_blood_type (blood_type),
                INDEX idx_email (email)
            )
        """)
        
        # Create recipients table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS recipients (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100),
                phone VARCHAR(15),
                blood_type VARCHAR(5) NOT NULL,
                units_needed INT NOT NULL,
                urgency VARCHAR(20) DEFAULT 'normal',
                hospital VARCHAR(100),
                status VARCHAR(20) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_blood_type (blood_type),
                INDEX idx_status (status)
            )
        """)
        
        # Insert default blood types if they don't exist
        blood_types = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
        for blood_type in blood_types:
            cursor.execute("""
                INSERT IGNORE INTO blood_inventory (blood_type, units) 
                VALUES (%s, %s)
            """, (blood_type, 0))
        
        connection.commit()
        logger.info("Database initialized successfully")
        return True
        
    except Error as e:
        logger.error(f"Database initialization error: {e}")
        return False
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

def token_required(f):
    """Decorator to require JWT token for protected routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(current_user_id, *args, **kwargs)
    
    return decorated

@app.route("/dashboard")
def index():
    return render_template("dashboard.html")   # lowercase


@app.route('/api/inventory', methods=['GET'])
@token_required
def get_inventory(current_user_id):
    """Get blood inventory data from database"""
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT blood_type, units, last_updated 
            FROM blood_inventory 
            ORDER BY blood_type
        """)
        
        inventory_data = cursor.fetchall()
        
        # Format the data for frontend
        formatted_data = []
        for item in inventory_data:
            formatted_data.append({
                'bloodType': item['blood_type'],
                'units': item['units'],
                'lastUpdated': item['last_updated'].isoformat() if item['last_updated'] else None,
                'status': get_stock_status(item['units'])
            })
        
        return jsonify(formatted_data)
        
    except Error as e:
        logger.error(f"Error fetching inventory: {e}")
        return jsonify({'error': 'Failed to fetch inventory data'}), 500
    
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/api/inventory/update', methods=['POST'])
@token_required
def update_inventory(current_user_id):
    """Update blood inventory"""
    data = request.get_json()
    
    if not data or 'blood_type' not in data or 'units' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    blood_type = data['blood_type']
    units = data['units']
    operation = data.get('operation', 'set')  # 'set', 'add', or 'subtract'
    
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        cursor = connection.cursor()
        
        if operation == 'set':
            cursor.execute("""
                UPDATE blood_inventory 
                SET units = %s, last_updated = CURRENT_TIMESTAMP 
                WHERE blood_type = %s
            """, (units, blood_type))
        elif operation == 'add':
            cursor.execute("""
                UPDATE blood_inventory 
                SET units = units + %s, last_updated = CURRENT_TIMESTAMP 
                WHERE blood_type = %s
            """, (units, blood_type))
        elif operation == 'subtract':
            cursor.execute("""
                UPDATE blood_inventory 
                SET units = GREATEST(0, units - %s), last_updated = CURRENT_TIMESTAMP 
                WHERE blood_type = %s
            """, (units, blood_type))
        
        if cursor.rowcount == 0:
            return jsonify({'error': 'Blood type not found'}), 404
        
        connection.commit()
        return jsonify({'message': 'Inventory updated successfully'})
        
    except Error as e:
        logger.error(f"Error updating inventory: {e}")
        return jsonify({'error': 'Failed to update inventory'}), 500
    
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/api/donors', methods=['GET'])
@token_required
def get_donors(current_user_id):
    """Get all donors"""
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM donors 
            WHERE status = 'active' 
            ORDER BY last_donation_date DESC
        """)
        
        donors = cursor.fetchall()
        
        # Format dates for JSON serialization
        for donor in donors:
            if donor['last_donation_date']:
                donor['last_donation_date'] = donor['last_donation_date'].isoformat()
            if donor['created_at']:
                donor['created_at'] = donor['created_at'].isoformat()
        
        return jsonify(donors)
        
    except Error as e:
        logger.error(f"Error fetching donors: {e}")
        return jsonify({'error': 'Failed to fetch donors'}), 500
    
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/api/recipients', methods=['GET'])
@token_required
def get_recipients(current_user_id):
    """Get all recipients"""
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM recipients 
            WHERE status IN ('pending', 'processing') 
            ORDER BY urgency DESC, created_at ASC
        """)
        
        recipients = cursor.fetchall()
        
        # Format dates for JSON serialization
        for recipient in recipients:
            if recipient['created_at']:
                recipient['created_at'] = recipient['created_at'].isoformat()
        
        return jsonify(recipients)
        
    except Error as e:
        logger.error(f"Error fetching recipients: {e}")
        return jsonify({'error': 'Failed to fetch recipients'}), 500
    
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats(current_user_id):
    """Get dashboard statistics"""
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Get total units
        cursor.execute("SELECT SUM(units) as total_units FROM blood_inventory")
        total_units = cursor.fetchone()['total_units'] or 0
        
        # Get critical stock count
        cursor.execute("SELECT COUNT(*) as critical_count FROM blood_inventory WHERE units < 5")
        critical_count = cursor.fetchone()['critical_count'] or 0
        
        # Get active donors count
        cursor.execute("SELECT COUNT(*) as donor_count FROM donors WHERE status = 'active'")
        donor_count = cursor.fetchone()['donor_count'] or 0
        
        # Get pending recipients count
        cursor.execute("SELECT COUNT(*) as recipient_count FROM recipients WHERE status IN ('pending', 'processing')")
        recipient_count = cursor.fetchone()['recipient_count'] or 0
        
        stats = {
            'totalUnits': total_units,
            'criticalStock': critical_count,
            'activeDonors': donor_count,
            'pendingRecipients': recipient_count
        }
        
        return jsonify(stats)
        
    except Error as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        return jsonify({'error': 'Failed to fetch dashboard statistics'}), 500
    
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection failed'}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, username, email, password_hash, role 
            FROM users 
            WHERE username = %s
        """, (username,))
        
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            # Generate JWT token
            token = jwt.encode({
                'user_id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'token': token,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'role': user['role']
                }
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Error as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500
    
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

def get_stock_status(units):
    """Determine stock status based on unit count"""
    if units < 5:
        return 'critical'
    elif units < 10:
        return 'warning'
    else:
        return 'healthy'

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    connection = get_db_connection()
    if connection:
        connection.close()
        return jsonify({'status': 'healthy', 'database': 'connected'})
    else:
        return jsonify({'status': 'unhealthy', 'database': 'disconnected'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.route("/_ping")
def _ping():
    return "ok"

if __name__ == '__main__':
    # Initialize database on startup
    if init_database():
        logger.info("Starting Blood Donation Management System API")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        logger.error("Failed to initialize database. Exiting.")
        exit(1)

