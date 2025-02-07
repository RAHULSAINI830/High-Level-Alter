from flask import Flask, request, jsonify, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import os
import jwt
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from bson.objectid import ObjectId
from functools import wraps
from flask_cors import CORS
from flask import session  # For storing user OAuth credentials


# Google OAuth2 and Analytics Setup
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For local testing only
CLIENT_SECRET_FILE = 'oauth2-credentials.json'  # OAuth2 credentials file path
SCOPES = ['https://www.googleapis.com/auth/analytics.readonly']
GA4_PROPERTY_ID = 'YOUR_GA4_PROPERTY_ID'  # Replace with your GA4 property ID

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

# Secret key for JWT
app.config['SECRET_KEY'] = 'b9c8d5a73944b7f924b5296acdf4cddc35e3475f0a1a32a0c451aee71d6c49b2'

# MongoDB setup (define client and users_collection globally)
try:
    client = MongoClient("mongodb+srv://sainirahul1009:z7TJMAdiqfAiHGRD@cluster0.3bmxr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
    db = client['social_dashboard']
    users_collection = db['users']  # Now this is globally defined and accessible
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

# Helper function to create JWT tokens
def generate_jwt_token(user_id):
    payload = {
        'user_id': str(user_id),
        'exp': datetime.now(timezone.utc) + timedelta(hours=1)  # Token valid for 1 hour
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

# Middleware to protect routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 403

        # Remove "Bearer " prefix if present
        if token.startswith('Bearer '):
            token = token[7:]

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
@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')

# Register a new user (POST request)
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json

    # Validate request data
    if not data or not all(key in data for key in ('name', 'email', 'password')):
        return jsonify({'error': 'Name, email, and password are required'}), 400

    # Check if user already exists
    if users_collection.find_one({'email': data['email']}):
        return jsonify({'error': 'User already exists'}), 400

    # Hash password and insert user into the database
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    user = {
        'name': data['name'],
        'email': data['email'],
        'password': hashed_password,
        'created_at': datetime.now(timezone.utc)
    }

    try:
        users_collection.insert_one(user)
    except Exception as e:
        return jsonify({'error': f'Error saving user to database: {str(e)}'}), 500

    return jsonify({'message': 'User registered successfully'}), 201

# User login (POST request)
# User login (POST request)
@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.json  # Get the request data
        print("Received POST data:", data)

        # Validate request data
        if not data or not all(key in data for key in ('email', 'password')):
            return jsonify({'error': 'Email and password are required'}), 400

        # Find the user by email
        user = users_collection.find_one({'email': data['email']})

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Validate password
        if not check_password_hash(user['password'], data['password']):
            return jsonify({'error': 'Invalid password'}), 401

        # Generate JWT token
        token = generate_jwt_token(user['_id'])
        return jsonify({'token': token, 'message': 'Login successful'}), 200

    except Exception as e:
        print(f"Error during login: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


# Route to redirect user to Google's OAuth page
@app.route('/auth/google')
def auth_google():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('auth_callback', _external=True)
    )
    authorization_url, _ = flow.authorization_url(prompt='consent')
    return redirect(authorization_url)

@app.route('/auth/callback')
def auth_callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('auth_callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    # Store credentials in session
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    return redirect(url_for('dashboard_page'))


    # Validate user credentials
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if not check_password_hash(user['password'], data['password']):
        return jsonify({'error': 'Invalid password'}), 401

    # Generate JWT token
    token = generate_jwt_token(user['_id'])
    return jsonify({'token': token, 'message': 'Login successful'}), 200

@app.route('/analytics', methods=['GET'])
def fetch_analytics_data():
    if 'credentials' not in session:
        return jsonify({'error': 'User not authenticated. Please connect to Google Analytics first.'}), 401

    # Use stored credentials
    credentials = Credentials(**session['credentials'])
    analytics = build('analyticsdata', 'v1beta', credentials=credentials)

    try:
        # Request body to fetch sessions and active users
        request_body = {
            'dateRanges': [{'startDate': '30daysAgo', 'endDate': 'today'}],
            'metrics': [
                {'name': 'activeUsers'},
                {'name': 'sessions'},
                {'name': 'screenPageViews'}
            ],
        }

        response = analytics.properties().runReport(
            property=f'properties/{GA4_PROPERTY_ID}',
            body=request_body
        ).execute()

        # Extract the metrics from the response
        data = {
            'activeUsers': response['rows'][0]['metricValues'][0]['value'],
            'sessions': response['rows'][0]['metricValues'][1]['value'],
            'screenPageViews': response['rows'][0]['metricValues'][2]['value']
        }
        return jsonify(data)
    except Exception as e:
        print(f"Error fetching Google Analytics data: {str(e)}")
        return jsonify({'error': str(e)}), 500


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

@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_user_profile(current_user):
    try:
        user_profile = {
            'name': current_user['name'],
            'email': current_user['email']
        }
        return jsonify(user_profile), 200
    except Exception as e:
        return jsonify({'error': f'Error retrieving user profile: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
