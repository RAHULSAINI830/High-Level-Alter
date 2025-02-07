from flask import Flask, request, jsonify, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from bson.objectid import ObjectId
from functools import wraps
from flask_cors import CORS
from flask_mail import Mail, Message
import random

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True, 
     expose_headers=["Authorization"], allow_headers=["Authorization", "Content-Type"])# Secret key for JWT
app.config['SECRET_KEY'] = 'b9c8d5a73944b7f924b5296acdf4cddc35e3475f0a1a32a0c451aee71d6c49b2'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rahul.saini@zentrades.pro'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'Rahul@830'   # Replace with your email app password
mail = Mail(app)

# MongoDB setup
try:
    client = MongoClient("mongodb+srv://sainirahul1009:z7TJMAdiqfAiHGRD@cluster0.3bmxr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
    db = client['social_dashboard']
    users_collection = db['users']
    otp_collection = db['otp_verification']
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

# Helper function to generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Helper function to send OTP
def send_otp_email(email, otp):
    msg = Message(subject="Your OTP Verification Code",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"Your OTP for verification is: {otp}. It is valid for 10 minutes."
    mail.send(msg)

# Generate JWT tokens
def generate_jwt_token(user_id):
    payload = {
        'user_id': str(user_id),
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)  # Extend validity to 24 hours
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token



# Middleware to protect routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Log all headers for debugging
        print("All Request Headers:", dict(request.headers))

        token = request.headers.get('Authorization')
        print(f"Authorization Header Received: {token}")

        if not token:
            return jsonify({'error': 'Token is missing'}), 403

        if token.startswith('Bearer '):
            token = token.split(' ')[1]

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_collection.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user:
                return jsonify({'error': 'User not found'}), 404

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 403

        return f(current_user, *args, **kwargs)
    return decorated

# Root route
@app.route('/')
def home():
    return redirect(url_for('login_page'))

# Registration page route
@app.route('/register')
def register_page():
    return render_template('register.html')

# Login page route
@app.route('/login')
def login_page():
    return render_template('login.html')

# Dashboard page route
@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard_page(current_user):
    return jsonify({
        'user': {
            'name': current_user['name'],
            'email': current_user['email'],
            'created_at': current_user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        }
    }), 200




# Step 1: Send OTP during registration
@app.route('/auth/send-otp', methods=['POST'])
def send_otp():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    # Check if email is already registered
    if users_collection.find_one({'email': email}):
        return jsonify({'error': 'Email is already registered'}), 400

    otp = generate_otp()
    otp_collection.insert_one({'email': email, 'otp': otp, 'created_at': datetime.now(timezone.utc)})

    # Send OTP email
    send_otp_email(email, otp)
    return jsonify({'message': 'OTP sent to email'}), 200

# Step 2: Verify OTP
@app.route('/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({'error': 'Email and OTP are required'}), 400

    otp_entry = otp_collection.find_one({'email': email, 'otp': otp})
    if not otp_entry:
        return jsonify({'error': 'Invalid OTP'}), 400

    return jsonify({'message': 'OTP verified'}), 200


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    print("Received POST data:", data)

    # Validate request data
    if not data or not all(key in data for key in ('email', 'password')):
        return jsonify({'error': 'Email and password are required'}), 400

    user = users_collection.find_one({'email': data['email']})

    # Validate user credentials
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if not check_password_hash(user['password'], data['password']):
        return jsonify({'error': 'Invalid password'}), 401

    # Generate JWT token
    token = generate_jwt_token(user['_id'])
    return jsonify({'token': token, 'message': 'Login successful'}), 200

# Registration after OTP verification
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json

    if not data or not all(key in data for key in ('name', 'email', 'password', 'otp')):
        return jsonify({'error': 'Name, email, password, and OTP are required'}), 400

    otp_entry = otp_collection.find_one({'email': data['email'], 'otp': data['otp']})
    if not otp_entry:
        return jsonify({'error': 'Invalid OTP'}), 400

    if users_collection.find_one({'email': data['email']}):
        return jsonify({'error': 'User already exists'}), 400

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    user = {
        'name': data['name'],
        'email': data['email'],
        'password': hashed_password,
        'created_at': datetime.now(timezone.utc)
    }

    users_collection.insert_one(user)
    otp_collection.delete_one({'email': data['email']})  # Clean OTP after success
    return jsonify({'message': 'User registered successfully'}), 201

# Step 3: Forgot password - send OTP
@app.route('/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'No account associated with this email'}), 404

    otp = generate_otp()
    otp_collection.insert_one({'email': email, 'otp': otp, 'created_at': datetime.now(timezone.utc)})
    send_otp_email(email, otp)
    return jsonify({'message': 'OTP sent to your email'}), 200

# Step 4: Reset password
@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    if not email or not otp or not new_password:
        return jsonify({'error': 'Email, OTP, and new password are required'}), 400

    otp_entry = otp_collection.find_one({'email': email, 'otp': otp})
    if not otp_entry:
        return jsonify({'error': 'Invalid or expired OTP'}), 400

    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    users_collection.update_one({'email': email}, {'$set': {'password': hashed_password}})
    otp_collection.delete_one({'email': email})  # Clean OTP after success
    return jsonify({'message': 'Password reset successful'}), 200

# Protected route
@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    return jsonify({
        'message': f'Hello {current_user["name"]}, you have access to this protected route!',
        'user': {
            'name': current_user['name'],
            'email': current_user['email'],
            'created_at': current_user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        }
    }), 200

if __name__ == '__main__':
    app.run(debug=True)
