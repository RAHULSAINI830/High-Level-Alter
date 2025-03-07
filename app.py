from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
import os
import jwt
from datetime import datetime, timedelta, timezone
import random
import secrets  # For secure token generation
from pymongo import MongoClient
from bson.objectid import ObjectId
from functools import wraps
from flask_cors import CORS
from flask_mail import Mail, Message
import requests
import json

# ================= Configuration =================
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
CLIENT_SECRET_FILE = 'credentials.json'
SCOPES = ['https://www.googleapis.com/auth/analytics.readonly']
GA4_PROPERTY_ID = '376596938'

CALENDAR_CREDENTIALS_FILE = 'calendar_credentials.json'
GOOGLE_CALENDAR_SCOPES = ['https://www.googleapis.com/auth/calendar']

SERVICE_ACCOUNT_KEY_PATH = 'service-account-key.json'
GBP_ACCOUNT_ID = os.getenv('2018567491275164845')

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'b9c8d5a73944b7f924b5296acdf4cddc35e3475f0a1a32a0c451aee71d6c49b2'

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rahul.saini@zentrades.pro'
app.config['MAIL_PASSWORD'] = 'Rahul@902'
app.config['MAIL_DEFAULT_SENDER'] = ('Your Name', 'your-email@gmail.com')
mail = Mail(app)

# reCAPTCHA configuration
app.config['RECAPTCHA_SITE_KEY'] = '6Lfc3dIqAAAAAJ_JoVxkkHGu-rE7CrgnXFwIFBsd'
app.config['RECAPTCHA_SECRET_KEY'] = '6Lfc3dIqAAAAAMJEj9-LrGfzPznsk_DfWiTi-K2n'

# ================= MongoDB Setup =================
try:
    client = MongoClient("mongodb+srv://sainirahul1009:z7TJMAdiqfAiHGRD@cluster0.3bmxr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
    db = client['social_dashboard']
    users_collection = db['users']
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

# ================= Google Business Profile Clients =================
bp_service = None
bp_performance_service = None
if os.path.exists(SERVICE_ACCOUNT_KEY_PATH) and GBP_ACCOUNT_ID:
    bp_scopes = ['https://www.googleapis.com/auth/business.manage']
    try:
        bp_credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_KEY_PATH, scopes=bp_scopes)
        bp_service = build('mybusinessbusinessinformation', 'v1', credentials=bp_credentials)
        bp_performance_service = build('businessprofileperformance', 'v1', credentials=bp_credentials)
    except Exception as e:
        print(f"Error creating Google Business Profile clients: {e}")

# ================= Helper Functions =================
def generate_jwt_token(user_id):
    payload = {
        'user_id': str(user_id),
        'exp': datetime.now(timezone.utc) + timedelta(hours=1)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

# Original token_required for endpoints requiring individual authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization') or session.get('jwtToken')
        if not token:
            return jsonify({'error': 'Token is missing'}), 403
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

def admin_required(f):
    @wraps(f)
    def decorated_admin(current_user, *args, **kwargs):
        if not current_user.get('is_admin'):
            return jsonify({'error': 'Admin privileges required.'}), 403
        return f(current_user, *args, **kwargs)
    return decorated_admin

# New decorator: token_or_admin_required allows access if either a valid token is present
# OR if an admin is logged in (stored under session['adminUser'])
def token_or_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization') or session.get('jwtToken')
        if token:
            if token.startswith('Bearer '):
                token = token[7:]
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user = users_collection.find_one({'_id': ObjectId(data['user_id'])})
                if not current_user:
                    return jsonify({'error': 'User not found'}), 404
                return f(current_user, *args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token has expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 403
        else:
            admin_user = session.get('adminUser')
            if admin_user:
                return f(admin_user, *args, **kwargs)
            return jsonify({'error': 'Authentication required'}), 403
    return decorated

# ---------------- Context Processor ----------------
@app.context_processor
def inject_current_user():
    token = session.get('jwtToken')
    if token:
        if token.startswith('Bearer '):
            token = token[7:]
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = users_collection.find_one({'_id': ObjectId(data['user_id'])})
            if user:
                user['_id'] = str(user['_id'])
                return {'current_user': user}
        except Exception as e:
            print("Error decoding token:", e)
    return {'current_user': None}

# ================= Page Routes =================
@app.route('/')
def home():
    return redirect(url_for('login_page'))

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/login')
def login_page():
    return render_template('login.html', recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')

@app.route('/otp-verification')
def otp_verification_page():
    return render_template('otp_verification.html')

@app.route('/reset-password')
def reset_password_request_page():
    return render_template('reset_password_request.html')

@app.route('/reset-password-otp')
def reset_password_otp_page():
    return render_template('reset_password_otp.html')

@app.route('/business-profile')
@token_required
def business_profile_page(current_user):
    return render_template('business_profile.html', user=current_user)

# Updated settings route:
# Now, if an admin logs in, the settings page will query and send the list of normal users (those created by that admin)
@app.route('/settings')
@token_required
@admin_required
def settings_page(current_user):
    created_users = list(users_collection.find({'created_by': current_user['_id']}))
    for user in created_users:
        user['_id'] = str(user['_id'])
    return render_template('settings.html', created_users=created_users)




@app.route('/widget/<admin_id>')
def chatbot_widget(admin_id):
    return render_template('widget.html', admin_id=admin_id)

# ---------------- Authentication Endpoints ----------------
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    if not data or not all(key in data for key in ('name', 'email', 'password')):
        return jsonify({'error': 'Name, email, and password are required'}), 400
    if users_collection.find_one({'email': data['email']}):
        return jsonify({'error': 'User already exists'}), 400
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    otp = str(random.randint(100000, 999999))
    otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    user = {
        'name': data['name'],
        'email': data['email'],
        'password': hashed_password,
        'created_at': datetime.now(timezone.utc),
        'is_verified': False,
        'otp': otp,
        'otp_expiry': otp_expiry,
        'is_admin': False  # Set to True manually for admin accounts
    }
    try:
        result = users_collection.insert_one(user)
        session['pending_user_id'] = str(result.inserted_id)
        print(f"OTP for {data['email']} is: {otp}")
        msg = Message('Your OTP Verification Code', recipients=[data['email']])
        msg.body = f"Your OTP code is: {otp}. It is valid for 10 minutes."
        mail.send(msg)
    except Exception as e:
        return jsonify({'error': f'Error saving user to database: {str(e)}'}), 500
    return jsonify({'message': 'User registered successfully. Please verify OTP sent to your email.'}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        recaptcha_response = data.get('recaptcha_response')
        if not recaptcha_response:
            return jsonify({'error': 'Captcha verification failed.'}), 400
        recaptcha_verify_url = "https://www.google.com/recaptcha/api/siteverify"
        recaptcha_payload = {'secret': app.config['RECAPTCHA_SECRET_KEY'], 'response': recaptcha_response}
        recaptcha_result = requests.post(recaptcha_verify_url, data=recaptcha_payload).json()
        if not recaptcha_result.get("success"):
            return jsonify({'error': 'Captcha verification failed.'}), 400
        if not data or not all(key in data for key in ('email', 'password')):
            return jsonify({'error': 'Email and password are required'}), 400
        user = users_collection.find_one({'email': data['email']})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        if not check_password_hash(user['password'], data['password']):
            return jsonify({'error': 'Invalid password'}), 401
        if not user.get('is_verified', False):
            session['pending_user_id'] = str(user['_id'])
            return jsonify({'requiresOtp': True, 'message': 'OTP verification required. Please verify OTP sent to your email.'}), 200
        token = generate_jwt_token(user['_id'])
        session['jwtToken'] = token
        # If the user is an admin, store their info in session for later use
        if user.get('is_admin'):
            session['adminUser'] = {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email']
            }
        return jsonify({'token': token, 'message': 'Login successful'}), 200
    except Exception as e:
        print(f"Error during login: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# ---------------- Google Analytics OAuth Endpoints ----------------
@app.route('/auth/google')
def auth_google():
    try:
        redirect_uri = url_for('auth_callback', _external=True)
        print("Generated redirect URI:", redirect_uri)
        flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE, scopes=SCOPES, redirect_uri=redirect_uri)
    except FileNotFoundError:
        return "OAuth credentials file not found. Please add credentials.json to your project.", 500
    authorization_url, _ = flow.authorization_url(prompt='consent')
    return redirect(authorization_url)

@app.route('/auth/callback')
def auth_callback():
    redirect_uri = url_for('auth_callback', _external=True)
    print("Generated redirect URI in callback:", redirect_uri)
    if 'error' in request.args:
        error = request.args.get("error")
        return f"Error returned in callback: {error}"
    if 'code' not in request.args:
        return "Missing code parameter in response. This likely means the OAuth flow did not complete successfully."
    flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE, scopes=SCOPES, redirect_uri=redirect_uri)
    flow.fetch_token(authorization_response=request.url)
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

# ---------------- Analytics Endpoint with Filters ----------------
@app.route('/analytics', methods=['GET'])
@token_or_admin_required
def fetch_analytics_data(current_user):
    if 'credentials' not in session:
        return jsonify({'error': 'User not authenticated. Please connect to Google Analytics first.'}), 401
    credentials = Credentials(**session['credentials'])
    analytics = build('analyticsdata', 'v1beta', credentials=credentials)
    try:
        request_body = {
            'dateRanges': [{
                'startDate': request.args.get('startDate', '30daysAgo'),
                'endDate': request.args.get('endDate', 'today')
            }],
            'metrics': [
                {'name': 'activeUsers'},
                {'name': 'sessions'},
                {'name': 'screenPageViews'},
                {'name': 'engagedSessions'},
                {'name': 'engagementRate'},
                {'name': 'averageSessionDuration'},
                {'name': 'newUsers'},
                {'name': 'totalRevenue'}
            ],
            'dimensions': [
                {'name': 'pagePath'},
                {'name': 'country'},
                {'name': 'deviceCategory'},
                {'name': 'eventName'}
            ]
        }
        dimension_filters = []
        if request.args.get('country'):
            country_value = request.args.get('country')
            dimension_filters.append({
                "filter": {
                    "fieldName": "country",
                    "stringFilter": {
                        "value": country_value,
                        "matchType": "CONTAINS"
                    }
                }
            })
        if request.args.get('device'):
            device_value = request.args.get('device')
            dimension_filters.append({
                "filter": {
                    "fieldName": "deviceCategory",
                    "stringFilter": {
                        "value": device_value,
                        "matchType": "EXACT"
                    }
                }
            })
        if request.args.get('event'):
            event_value = request.args.get('event')
            dimension_filters.append({
                "filter": {
                    "fieldName": "eventName",
                    "stringFilter": {
                        "value": event_value,
                        "matchType": "EXACT"
                    }
                }
            })
        if request.args.get('pagePath'):
            pagePath_value = request.args.get('pagePath')
            match_type = request.args.get('matchType', 'CONTAINS')
            dimension_filters.append({
                "filter": {
                    "fieldName": "pagePath",
                    "stringFilter": {
                        "value": pagePath_value,
                        "matchType": match_type
                    }
                }
            })
        if dimension_filters:
            request_body["dimensionFilter"] = {
                "andGroup": {
                    "expressions": dimension_filters
                }
            }
        response = analytics.properties().runReport(
            property=f'properties/{GA4_PROPERTY_ID}',
            body=request_body,
        ).execute()
        return jsonify(response)
    except Exception as e:
        print(f"Error fetching Google Analytics data: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ---------------- Google Business Profile Endpoints ----------------
@app.route('/google-business-profile', methods=['GET'])
def google_business_profile():
    if bp_service is None or not GBP_ACCOUNT_ID:
        return jsonify({'error': 'Business Profile integration is not configured.'}), 400
    try:
        parent = f"accounts/{GBP_ACCOUNT_ID}"
        response = bp_service.accounts().locations().list(parent=parent).execute()
        locations = response.get('locations', [])
        return jsonify(locations), 200
    except Exception as e:
        print("Error fetching Google Business Profile data:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/admin/chatbot', methods=['GET', 'POST'])
@token_required
@admin_required
def manage_chatbot(current_user):
    if request.method == 'GET':
        chatbot = db.chatbots.find_one({"admin_id": str(current_user['_id'])})
        if not chatbot:
            default_qa = [
                {"question": "What services do you offer?", "answer": "We offer a range of digital marketing services."},
                {"question": "How can I contact you?", "answer": "You can reach us via our contact page."}
            ]
            chatbot = {
                "admin_id": str(current_user['_id']),
                "predefined_qa": default_qa,
                "created_at": datetime.now(timezone.utc)
            }
            db.chatbots.insert_one(chatbot)
        return render_template('chatbot.html', chatbot=chatbot, user=current_user)
    elif request.method == 'POST':
        data = request.json
        updated_qa = data.get("predefined_qa")
        if updated_qa is None:
            return jsonify({"error": "No Q&A provided"}), 400
        db.chatbots.update_one(
            {"admin_id": str(current_user['_id'])},
            {"$set": {"predefined_qa": updated_qa}}
        )
        return jsonify({"message": "Chatbot data updated successfully."}), 200

@app.route('/chatbot/<admin_id>/message', methods=['POST'])
def chatbot_message(admin_id):
    data = request.json
    user_message = data.get("message", "").strip().lower()
    if not user_message:
        return jsonify({"error": "Message required"}), 400
    chatbot = db.chatbots.find_one({"admin_id": admin_id})
    if not chatbot:
        return jsonify({"error": "Chatbot not found"}), 404
    response = "I'm sorry, I didn't understand that."
    for qa in chatbot.get("predefined_qa", []):
        if qa["question"].lower() in user_message or user_message in qa["question"].lower():
            response = qa["answer"]
            break
    return jsonify({"response": response})

@app.route('/business-profile/performance', methods=['GET'])
def google_business_profile_performance():
    if bp_performance_service is None or not GBP_ACCOUNT_ID:
        return jsonify({'error': 'Business Profile Performance integration is not configured.'}), 400
    try:
        location_id = request.args.get('location_id')
        if not location_id:
            parent = f"accounts/{GBP_ACCOUNT_ID}"
            locations_response = bp_service.accounts().locations().list(parent=parent).execute()
            locations = locations_response.get('locations', [])
            if not locations:
                return jsonify({'error': 'No locations found for this account.'}), 404
            location_id = locations[0]['name'].split('/')[-1]
        six_months_ago = (datetime.now(timezone.utc) - timedelta(days=180)).strftime("%Y-%m-%d")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        request_body = {
            "dateRanges": [{"startDate": six_months_ago, "endDate": today}],
            "metrics": [
                {"name": "views"},
                {"name": "clicks"},
                {"name": "calls"}
            ]
        }
        parent = f"accounts/{GBP_ACCOUNT_ID}/locations/{location_id}"
        performance_response = bp_performance_service.accounts().locations().fetchReport(parent=parent, body=request_body).execute()
        return jsonify(performance_response), 200
    except Exception as e:
        print("Error fetching Google Business Profile performance data:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/send-performance-report', methods=['POST'])
@token_required
def send_performance_report(current_user):
    try:
        location_id = request.json.get('location_id')
        if not location_id:
            parent = f"accounts/{GBP_ACCOUNT_ID}"
            locations_response = bp_service.accounts().locations().list(parent=parent).execute()
            locations = locations_response.get('locations', [])
            if not locations:
                return jsonify({'error': 'No locations found for this account.'}), 404
            location_id = locations[0]['name'].split('/')[-1]
        six_months_ago = (datetime.now(timezone.utc) - timedelta(days=180)).strftime("%Y-%m-%d")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        performance_request_body = {
            "dateRanges": [{"startDate": six_months_ago, "endDate": today}],
            "metrics": [
                {"name": "views"},
                {"name": "clicks"},
                {"name": "calls"}
            ]
        }
        parent = f"accounts/{GBP_ACCOUNT_ID}/locations/{location_id}"
        performance_response = bp_performance_service.accounts().locations().fetchReport(parent=parent, body=performance_request_body).execute()
        reviews_response = bp_service.accounts().locations().reviews().list(
            parent=f'accounts/{GBP_ACCOUNT_ID}/locations/{location_id}'
        ).execute()
        reviews = reviews_response.get('reviews', [])
        email_body = f"Performance Report (Last 6 Months):\n{json.dumps(performance_response, indent=2)}\n\nReviews:\n{json.dumps(reviews, indent=2)}"
        msg = Message(
            subject="Your 6-Month Business Profile Report",
            recipients=[current_user['email']],
            body=email_body
        )
        mail.send(msg)
        return jsonify({'message': 'Performance report email sent successfully.'}), 200
    except Exception as e:
        print("Error sending performance report:", e)
        return jsonify({'error': str(e)}), 500

# ---------------- OTP and Password Reset Endpoints ----------------
@app.route('/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    if not data or 'otp' not in data:
        return jsonify({'error': 'OTP is required'}), 400
    pending_user_id = session.get('pending_user_id')
    if not pending_user_id:
        return jsonify({'error': 'No pending OTP verification found.'}), 400
    user = users_collection.find_one({'_id': ObjectId(pending_user_id)})
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    otp_expiry = user.get('otp_expiry')
    if otp_expiry:
        if otp_expiry.tzinfo is None:
            otp_expiry = otp_expiry.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > otp_expiry:
            return jsonify({'error': 'OTP has expired. Please request a new one.'}), 400
    if str(user.get('otp')) != str(data['otp']):
        return jsonify({'error': 'Invalid OTP.'}), 400
    users_collection.update_one(
        {'_id': ObjectId(pending_user_id)},
        {'$set': {'is_verified': True}, '$unset': {'otp': "", 'otp_expiry': ""}}
    )
    session.pop('pending_user_id', None)
    return jsonify({'message': 'OTP verified successfully. You can now log in.'}), 200

@app.route('/auth/resend-otp', methods=['POST'])
def resend_otp():
    pending_user_id = session.get('pending_user_id')
    if not pending_user_id:
        return jsonify({'error': 'No pending OTP verification found.'}), 400
    user = users_collection.find_one({'_id': ObjectId(pending_user_id)})
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    new_otp = str(random.randint(100000, 999999))
    new_otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    users_collection.update_one(
        {'_id': ObjectId(pending_user_id)},
        {'$set': {'otp': new_otp, 'otp_expiry': new_otp_expiry}}
    )
    print(f"Resent OTP for {user['email']} is: {new_otp}")
    msg = Message('Your New OTP Verification Code', recipients=[user['email']])
    msg.body = f"Your new OTP code is: {new_otp}. It is valid for 10 minutes."
    mail.send(msg)
    return jsonify({'message': 'OTP resent successfully.'}), 200

@app.route('/auth/reset-password-request', methods=['POST'])
def reset_password_request():
    data = request.json
    if not data or 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400
    email = data['email']
    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'User with this email not found.'}), 404
    reset_otp = str(random.randint(100000, 999999))
    reset_otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    users_collection.update_one(
        {'_id': user['_id']},
        {'$set': {'reset_otp': reset_otp, 'reset_otp_expiry': reset_otp_expiry}}
    )
    session['pending_reset_email'] = email
    print(f"Reset OTP for {email} is: {reset_otp}")
    msg = Message('Your Password Reset OTP', recipients=[email])
    msg.body = f"Your password reset OTP is: {reset_otp}. It is valid for 10 minutes."
    mail.send(msg)
    return jsonify({'message': 'Reset OTP sent to your email.'}), 200

@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    if not data or not all(k in data for k in ('otp', 'new_password', 'confirm_password')):
        return jsonify({'error': 'OTP, new password and confirm password are required.'}), 400
    if data['new_password'] != data['confirm_password']:
        return jsonify({'error': 'Passwords do not match.'}), 400
    email = session.get('pending_reset_email')
    if not email:
        return jsonify({'error': 'No pending password reset request found.'}), 400
    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'User not found.'}), 404
    reset_otp = user.get('reset_otp')
    reset_otp_expiry = user.get('reset_otp_expiry')
    if not reset_otp or not reset_otp_expiry:
        return jsonify({'error': 'No reset OTP found. Please request a new one.'}), 400
    if reset_otp_expiry.tzinfo is None:
        reset_otp_expiry = reset_otp_expiry.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > reset_otp_expiry:
        return jsonify({'error': 'Reset OTP has expired. Please request a new one.'}), 400
    if str(reset_otp) != str(data['otp']):
        return jsonify({'error': 'Invalid reset OTP.'}), 400
    new_hashed_password = generate_password_hash(data['new_password'], method='pbkdf2:sha256')
    users_collection.update_one(
        {'_id': user['_id']},
        {'$set': {'password': new_hashed_password}, '$unset': {'reset_otp': "", 'reset_otp_expiry': ""}}
    )
    session.pop('pending_reset_email', None)
    return jsonify({'message': 'Password updated successfully. Please log in with your new password.'}), 200

# ---------------- Admin-Only Endpoints ----------------
@app.route('/auth/invite-user', methods=['POST'])
@token_required
@admin_required
def invite_user(current_user):
    data = request.json
    if not data or not all(k in data for k in ('email', 'password')):
        return jsonify({'error': 'Email and password are required.'}), 400
    email = data['email']
    if users_collection.find_one({'email': email}):
        return jsonify({'error': 'User already exists with this email.'}), 400
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    # Auto-verify the user upon invite
    new_user = {
        'name': '',
        'email': email,
        'password': hashed_password,
        'created_at': datetime.now(timezone.utc),
        'is_verified': True,  # Auto-verify without OTP
        'is_admin': False,
        'created_by': current_user['_id']
    }
    try:
        result = users_collection.insert_one(new_user)
        # Optionally, you can send an email notifying the invited user of their account details
        msg = Message('Invitation to join Social Dashboard', recipients=[email])
        msg.body = f"You have been invited to join the Social Dashboard. Your account has been created and verified. Please log in using your credentials."
        mail.send(msg)
        return jsonify({'message': 'User invited and auto-verified successfully. An email was sent to the user.'}), 200
    except Exception as e:
        return jsonify({'error': f'Error inviting user: {str(e)}'}), 500


@app.route('/auth/confirm-invite', methods=['GET'])
def confirm_invite():
    token = request.args.get('token')
    if not token:
        return "Invalid or missing token.", 400
    user = users_collection.find_one({'invite_token': token})
    if not user:
        return "Invalid token or user not found.", 400
    # Mark the user as verified and remove the invite token
    users_collection.update_one(
        {'_id': user['_id']},
        {'$set': {'is_verified': True}, '$unset': {'invite_token': ""}}
    )
    # Optionally, you can render a template here to show a nice confirmation page
    return render_template('invite_confirmed.html')

@app.route('/api/users', methods=['GET'])
@token_or_admin_required
@admin_required
def list_users(current_user):
    try:
        # Only list users that were created by the admin
        users = list(users_collection.find({'created_by': current_user['id'] if 'id' in current_user else current_user['_id']}))
        for user in users:
            user['_id'] = str(user['_id'])
            if 'created_at' in user:
                user['created_at'] = user['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            user.pop('password', None)
            user.pop('otp', None)
            user.pop('otp_expiry', None)
            user.pop('invite_token', None)
            user.pop('reset_otp', None)
            user.pop('reset_otp_expiry', None)
            user['created_by'] = str(user.get('created_by', ''))
        return jsonify(users), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
@token_or_admin_required
@admin_required
def update_user(current_user, user_id):
    data = request.json
    try:
        update_data = {}
        if 'name' in data:
            update_data['name'] = data['name']
        if 'email' in data:
            update_data['email'] = data['email']
        if 'is_admin' in data:
            update_data['is_admin'] = data['is_admin']
        if update_data:
            users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
            return jsonify({'message': 'User updated successfully.'}), 200
        else:
            return jsonify({'error': 'No valid fields to update.'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['DELETE'])
@token_or_admin_required
@admin_required
def delete_user(current_user, user_id):
    try:
        users_collection.delete_one({'_id': ObjectId(user_id)})
        return jsonify({'message': 'User deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------------- Local Calendar Endpoints ----------------
events_collection = db['events']

@app.route('/calendar/events', methods=['GET'])
@token_or_admin_required
def get_events(current_user):
    try:
        events = list(events_collection.find({"user_id": str(current_user['_id'] if '_id' in current_user else current_user['id'])}))
        for event in events:
            event['_id'] = str(event['_id'])
        return jsonify(events), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/calendar/events', methods=['POST'])
@token_or_admin_required
def add_event(current_user):
    data = request.json
    required_fields = ['title', 'start', 'end']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Title, start date, and end date are required.'}), 400
    event = {
        'user_id': str(current_user['_id'] if '_id' in current_user else current_user['id']),
        'title': data['title'],
        'start': data['start'],
        'end': data['end'],
        'description': data.get('description', ''),
        'created_at': datetime.now(timezone.utc)
    }
    try:
        result = events_collection.insert_one(event)
        event['_id'] = str(result.inserted_id)
        return jsonify(event), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/calendar/events/<event_id>', methods=['PUT'])
@token_or_admin_required
def update_event(current_user, event_id):
    data = request.json
    update_fields = {}
    if 'title' in data:
        update_fields['title'] = data['title']
    if 'start' in data:
        update_fields['start'] = data['start']
    if 'end' in data:
        update_fields['end'] = data['end']
    if 'description' in data:
        update_fields['description'] = data['description']
    if not update_fields:
        return jsonify({'error': 'No valid fields to update.'}), 400
    try:
        events_collection.update_one(
            {'_id': ObjectId(event_id), 'user_id': str(current_user['_id'] if '_id' in current_user else current_user['id'])},
            {'$set': update_fields}
        )
        return jsonify({'message': 'Event updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/calendar/events/<event_id>', methods=['DELETE'])
@token_or_admin_required
def delete_event(current_user, event_id):
    try:
        events_collection.delete_one({'_id': ObjectId(event_id), 'user_id': str(current_user['_id'] if '_id' in current_user else current_user['id'])})
        return jsonify({'message': 'Event deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------------- Google Calendar Integration Endpoints ----------------
@app.route('/auth/google-calendar')
def auth_google_calendar():
    try:
        flow = Flow.from_client_secrets_file(
            CALENDAR_CREDENTIALS_FILE,
            scopes=GOOGLE_CALENDAR_SCOPES,
            redirect_uri=url_for('auth_google_calendar_callback', _external=True)
        )
    except FileNotFoundError:
        return "OAuth credentials file not found. Please add calendar_credentials.json to your project.", 500
    authorization_url, state = flow.authorization_url(prompt='consent', access_type='offline')
    session['google_calendar_state'] = state
    return redirect(authorization_url)

@app.route('/calendar/callback')
def auth_google_calendar_callback():
    state = session.get('google_calendar_state')
    flow = Flow.from_client_secrets_file(
        CALENDAR_CREDENTIALS_FILE,
        scopes=GOOGLE_CALENDAR_SCOPES,
        state=state,
        redirect_uri=url_for('auth_google_calendar_callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['google_calendar_credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    return redirect(url_for('dashboard_page'))

@app.route('/google-calendar/events', methods=['GET'])
@token_or_admin_required
def get_google_calendar_events(current_user):
    if 'google_calendar_credentials' not in session:
        return jsonify({'error': 'Google Calendar not connected.'}), 401
    credentials = Credentials(**session['google_calendar_credentials'])
    try:
        service = build('calendar', 'v3', credentials=credentials)
        now = datetime.utcnow().isoformat() + 'Z'
        events_result = service.events().list(
            calendarId='primary',
            timeMin=now,
            maxResults=10,
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        events = events_result.get('items', [])
        return jsonify(events), 200
    except Exception as e:
        print("Error in /google-calendar/events:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/google-calendar/events', methods=['POST'])
@token_or_admin_required
def create_google_calendar_event(current_user):
    if 'google_calendar_credentials' not in session:
        return jsonify({'error': 'Google Calendar not connected.'}), 401
    data = request.json
    required_fields = ['summary', 'start', 'end']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Summary, start, and end times are required.'}), 400

    def format_datetime(dt_str):
        if len(dt_str) == 16:
            return dt_str + ":00Z"
        return dt_str

    start_formatted = format_datetime(data['start'])
    end_formatted = format_datetime(data['end'])
    credentials = Credentials(**session['google_calendar_credentials'])
    try:
        service = build('calendar', 'v3', credentials=credentials)
        event_body = {
            'summary': data['summary'],
            'description': data.get('description', ''),
            'start': {
                'dateTime': start_formatted,
                'timeZone': data.get('timeZone', 'UTC'),
            },
            'end': {
                'dateTime': end_formatted,
                'timeZone': data.get('timeZone', 'UTC'),
            },
        }
        event = service.events().insert(calendarId='primary', body=event_body).execute()
        return jsonify(event), 201
    except Exception as e:
        print("Error creating Google Calendar event:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/google-calendar/events/<event_id>', methods=['PUT'])
@token_or_admin_required
def update_google_calendar_event(current_user, event_id):
    if 'google_calendar_credentials' not in session:
        return jsonify({'error': 'Google Calendar not connected.'}), 401
    data = request.json
    credentials = Credentials(**session['google_calendar_credentials'])
    try:
        service = build('calendar', 'v3', credentials=credentials)
        event = service.events().get(calendarId='primary', eventId=event_id).execute()
        if 'summary' in data:
            event['summary'] = data['summary']
        if 'description' in data:
            event['description'] = data['description']
        if 'start' in data:
            event['start'] = {'dateTime': data['start'], 'timeZone': data.get('timeZone', 'UTC')}
        if 'end' in data:
            event['end'] = {'dateTime': data['end'], 'timeZone': data.get('timeZone', 'UTC')}
        updated_event = service.events().update(calendarId='primary', eventId=event_id, body=event).execute()
        return jsonify(updated_event), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/google-calendar/events/<event_id>', methods=['DELETE'])
@token_or_admin_required
def delete_google_calendar_event(current_user, event_id):
    if 'google_calendar_credentials' not in session:
        return jsonify({'error': 'Google Calendar not connected.'}), 401
    credentials = Credentials(**session['google_calendar_credentials'])
    try:
        service = build('calendar', 'v3', credentials=credentials)
        service.events().delete(calendarId='primary', eventId=event_id).execute()
        return jsonify({'message': 'Event deleted successfully.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------------- Other Endpoints ----------------
@app.route('/protected', methods=['GET'])
@token_or_admin_required
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
@token_or_admin_required
def get_user_profile(current_user):
    try:
        user_profile = {
            'name': current_user['name'],
            'email': current_user['email'],
            'is_admin': current_user.get('is_admin', False)
        }
        return jsonify(user_profile), 200
    except Exception as e:
        return jsonify({'error': f'Error retrieving user profile: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
