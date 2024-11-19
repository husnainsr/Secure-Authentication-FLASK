from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
import sqlite3
from datetime import datetime, timedelta
import os
import bcrypt
from itsdangerous import URLSafeTimedSerializer
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import re
import random
from functools import wraps
import time
from collections import defaultdict

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.permanent_session_lifetime = timedelta(minutes=30)  # Set session timeout to 30 minutes

s = URLSafeTimedSerializer(app.secret_key)

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
DB_PATH = os.path.join(DB_DIR, 'secure_auth.db')

LOGIN_ATTEMPTS = defaultdict(list)
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 900  # 15 minutes in seconds
PASSWORD_BLACKLIST = {'password123', '12345678', 'qwerty123', 'admin123'}  # Add more common passwords

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "your_secure_admin_password")  # Set this in your .env file

def is_password_compromised(password):
    """Check if password is in common password list or too simple"""
    if password.lower() in PASSWORD_BLACKLIST:
        return True
    # Check for keyboard patterns
    keyboard_patterns = ['qwerty', 'asdfgh', '123456', '987654']
    return any(pattern in password.lower() for pattern in keyboard_patterns)

def check_rate_limit(ip_address):
    """Rate limiting function"""
    current_time = time.time()
    # Remove attempts older than lockout time
    LOGIN_ATTEMPTS[ip_address] = [
        attempt for attempt in LOGIN_ATTEMPTS[ip_address] 
        if current_time - attempt < LOCKOUT_TIME
    ]
    
    if len(LOGIN_ATTEMPTS[ip_address]) >= MAX_ATTEMPTS:
        return False
    LOGIN_ATTEMPTS[ip_address].append(current_time)
    return True

def connect_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row  
    return connection


def setup_database():
    """
    Set up the database and create the users table if it doesn't exist.
    Implemented by Khadijah.
    """
    conn = connect_db()
    cursor = conn.cursor()

    # Create users table with is_verified column
    cursor.execute('''  
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            registration_date TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            otp TEXT,  
            otp_expiration TEXT 
        )
    ''')

    # Check if the is_verified column exists, if not add it
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'is_verified' not in columns:
        cursor.execute('ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0;')
    if 'otp' not in columns:
        cursor.execute('ALTER TABLE users ADD COLUMN otp TEXT;')  
    if 'otp_expiration' not in columns:
        cursor.execute('ALTER TABLE users ADD COLUMN otp_expiration TEXT;')    

    conn.commit()
    cursor.close()
    conn.close()


# Route to render registration form
@app.route('/')
def index():
    return render_template('register.html')



def generate_otp(length=6):
    """Generate a random numeric OTP of specified length."""
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])


def send_otp_email(email, otp):
    """Send OTP to the user's email address with a beautiful template."""
    sender_email = os.getenv("EMAIL")
    receiver_email = email
    subject = "🔐 Your Secure Auth Verification Code"

    # HTML Email Template
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background: linear-gradient(135deg, #f5f7fa 0%, #e8ecf3 100%);
                border-radius: 10px;
            }}
            .header {{
                text-align: center;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border-radius: 10px 10px 0 0;
            }}
            .content {{
                padding: 30px;
                background: white;
                border-radius: 0 0 10px 10px;
            }}
            .otp-box {{
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
                font-size: 32px;
                letter-spacing: 5px;
                margin: 20px 0;
                font-weight: bold;
                color: #4a4a4a;
            }}
            .footer {{
                text-align: center;
                margin-top: 20px;
                font-size: 12px;
                color: #666;
            }}
            .warning {{
                color: #dc3545;
                font-size: 14px;
                margin-top: 15px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Secure Auth</h1>
            </div>
            <div class="content">
                <h2>Hello! 👋</h2>
                
                <p>Welcome to our secure community! 🌟</p>
                
                <p>Here's your verification code to complete your registration:</p>
                
                <div class="otp-box">
                    {otp}
                </div>
                
                <p>⚡ This code will expire in 5 minutes for your security.</p>
                
                <p>Here's what you need to know:</p>
                <ul>
                    <li>🔑 Keep this code private</li>
                    <li>⏰ Act quickly - it expires soon!</li>
                    <li>🚫 Never share this code with anyone</li>
                    <li>❓ Our support team will never ask for this code</li>
                </ul>
                
                <p class="warning">
                    ⚠️ If you didn't request this code, please ignore this email.
                </p>
                
                <p>Stay secure! 🛡️</p>
                
                <div class="footer">
                    <p>🔒 Secure Auth - Protecting Your Digital World</p>
                    <p>This is an automated message, please do not reply.</p>
                    <p>© {datetime.now().year} Secure Auth. All rights reserved.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

    # Plain text version for email clients that don't support HTML
    text_content = f"""
    🔒 Secure Auth - Verification Code

    Hello! 👋

    Your verification code is: {otp}

    ⚠️ This code will expire in 5 minutes.
    
    🔑 Keep this code private and never share it with anyone.
    
    If you didn't request this code, please ignore this email.

    Stay secure! 🛡️
    """

    message = MIMEMultipart("alternative")
    message["From"] = f"Secure Auth <{sender_email}>"
    message["To"] = receiver_email
    message["Subject"] = subject

    # Add plain-text and HTML versions to the message
    message.attach(MIMEText(text_content, "plain"))
    message.attach(MIMEText(html_content, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            PASSWORD = os.getenv("PASSWORD")
            server.login(sender_email, PASSWORD)
            server.sendmail(sender_email, receiver_email, message.as_string())
            print("✅ OTP email sent successfully!")
    except Exception as e:
        print(f"❌ Error sending OTP email: {e}")

# Route to register a new user and insert into the database
@app.route('/register', methods=['POST'])
def register():
    """Enhanced registration with additional security checks"""
    username = request.form['username'].strip()
    email = request.form['email'].strip()
    password = request.form['password']
    registration_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # IP-based rate limiting
    if not check_rate_limit(request.remote_addr):
        flash("Too many registration attempts. Please try again later.", "danger")
        return render_template('register.html'), 429

    # Enhanced username validation
    if not re.match(r'^[a-zA-Z0-9_-]{3,32}$', username):
        flash("Username must be 3-32 characters and contain only letters, numbers, underscores, and hyphens.", "danger")
        return render_template('register.html')

    # Enhanced password requirements
    if (len(password) < 12 or  # Increased minimum length
        not re.search(r'[A-Z]', password) or 
        not re.search(r'[a-z]', password) or 
        not re.search(r'\d', password) or
        not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):  # Special characters
        flash("Password must be at least 12 characters and contain uppercase, lowercase, numbers, and special characters.", "danger")
        return render_template('register.html')

    # Check for compromised passwords
    if is_password_compromised(password):
        flash("This password is too common. Please choose a stronger password.", "danger")
        return render_template('register.html')

    # Email verification
    email_pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_pattern, email):
        flash("Please enter a valid email address.", "danger")
        return render_template('register.html')
    
    # Email Verification
    email_pattern = r'^[a-zA-Z0-9_.+-]+@gmail\.com$'
    if not re.match(email_pattern, email):
        flash("Please enter a valid Gmail address (example@gmail.com).", "danger")
        return render_template('register.html')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Generate OTP for registration verification
    otp = generate_otp()
    otp_expiration = datetime.now() + timedelta(minutes=5)
    otp_expiration_str = otp_expiration.strftime('%Y-%m-%d %H:%M:%S')

    setup_database()  # Ensure the database is set up before registering a user

    conn = connect_db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users 
            (username, email, password_hash, registration_date, otp, otp_expiration) 
            VALUES (?, ?, ?, ?, ?, ?)
            """, 
            (username, email, hashed_password, registration_date, otp, otp_expiration_str))
        conn.commit()
        
        send_otp_email(email, otp)
        session['registration_email'] = email
        flash("Registration initiated! Please check your email for OTP to verify your account.", "info")
        return redirect(url_for('verify_registration'))
    except sqlite3.IntegrityError:
        flash("This email address is already registered. Please use a different email or log in.", "danger")
        return render_template('register.html')
    except sqlite3.Error as e:
        return jsonify({'error': str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route('/verify_registration', methods=['GET', 'POST'])
def verify_registration():
    """Handle OTP verification for registration."""
    if 'registration_email' not in session:
        flash("No pending registration found.", "warning")
        return redirect(url_for('register'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        email = session['registration_email']

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT otp, otp_expiration FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if user:
            stored_otp = user['otp']
            otp_expiration = datetime.strptime(user['otp_expiration'], '%Y-%m-%d %H:%M:%S')

            if datetime.now() > otp_expiration:
                flash("OTP has expired. Please register again.", "danger")
                cursor.close()
                conn.close()
                session.pop('registration_email', None)
                return redirect(url_for('register'))

            if entered_otp == stored_otp:
                cursor.execute("""
                    UPDATE users 
                    SET is_verified = 1, otp = NULL, otp_expiration = NULL 
                    WHERE email = ?
                    """, (email,))
                conn.commit()
                session.pop('registration_email', None)
                flash("Email verified successfully! You may now log in.", "success")
                return redirect(url_for('login'))
            else:
                flash("Invalid OTP. Please try again.", "danger")
        
        cursor.close()
        conn.close()
        return render_template('verify_registration.html')

    return render_template('verify_registration.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Enhanced login with additional security"""
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']
        
        # IP-based rate limiting
        if not check_rate_limit(request.remote_addr):
            flash("Account temporarily locked due to too many login attempts. Please try again later.", "danger")
            return render_template('login.html'), 429

        conn = connect_db()
        cursor = conn.cursor()
        
        try:
            # Use parameterized query to prevent SQL injection
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()

            if user:
                # Add delay to prevent timing attacks
                time.sleep(0.1)
                
                if bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
                    if not user['is_verified']:
                        flash("Please verify your email before logging in.", "warning")
                        return redirect(url_for('login'))

                    # Clear failed login attempts on successful login
                    LOGIN_ATTEMPTS[request.remote_addr].clear()
                    
                    # Generate and send OTP
                    otp = generate_otp()
                    otp_expiration = datetime.now() + timedelta(minutes=5)
                    otp_expiration_str = otp_expiration.strftime('%Y-%m-%d %H:%M:%S')

                    cursor.execute("""
                        UPDATE users 
                        SET otp = ?, 
                            otp_expiration = ?,
                            last_login_attempt = CURRENT_TIMESTAMP
                        WHERE email = ?
                    """, (otp, otp_expiration_str, email))
                    conn.commit()

                    send_otp_email(email, otp)
                    session['otp_user'] = email
                    
                    flash("An OTP has been sent to your email.", "info")
                    return redirect(url_for('verify_otp'))
                else:
                    flash("Invalid email or password.", "danger")
            else:
                # Use same message as invalid password to prevent user enumeration
                flash("Invalid email or password.", "danger")

        except Exception as e:
            flash("An error occurred. Please try again.", "danger")
            print(f"Login error: {str(e)}")  # Log the actual error securely
        finally:
            cursor.close()
            conn.close()

        return render_template('login.html')

    return render_template('login.html')



@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    """Handle OTP verification for 2FA."""
    if 'otp_user' not in session:
        flash("No OTP request found. Please log in.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        email = session['otp_user']

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT otp, otp_expiration FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if user:
            stored_otp = user['otp']
            otp_expiration = datetime.strptime(user['otp_expiration'], '%Y-%m-%d %H:%M:%S')

            if datetime.now() > otp_expiration:
                flash("OTP has expired. Please log in again.", "danger")
                cursor.close()
                conn.close()
                session.pop('otp_user', None)  # Nibras – OTP Session Management
                return redirect(url_for('login'))

            if entered_otp == stored_otp:
                flash("OTP verified successfully! You are now logged in.", "success")
                cursor.execute("UPDATE users SET otp = NULL, otp_expiration = NULL WHERE email = ?", (email,))
                conn.commit()
                cursor.close()
                conn.close()
                session.pop('otp_user', None)
                session.permanent = True  # Enable session expiry
                session['user'] = email
                session['last_activity'] = datetime.now().isoformat()  # Set initial activity timestamp
                return redirect(url_for('welcome'))
            else:
                flash("Invalid OTP. Please try again.", "danger")
        else:
            flash("User not found.", "danger")


        cursor.close()
        conn.close()
        return render_template('verify_otp.html')

    return render_template('verify_otp.html')



@app.route('/welcome')
def welcome():
    """Render the welcome page for logged-in users."""
    if 'user' not in session:
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))
    
    # Additional security check to ensure proper authentication flow
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT is_verified FROM users WHERE email = ?", (session['user'],))
        user = cursor.fetchone()
        
        if not user or not user['is_verified']:
            session.clear()  # Clear invalid session
            flash("Invalid access. Please login properly.", "danger")
            return redirect(url_for('login'))
            
    except sqlite3.Error as e:
        flash("An error occurred. Please try again.", "danger")
        return redirect(url_for('login'))
    finally:
        cursor.close()
        conn.close()
        
    return render_template('welcome.html', user=session['user'])



@app.route('/logout')
def logout():
    """Log the user out by clearing the session."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/show_all_users', methods=['GET'])
def show_all_users():
    conn = connect_db()
    cursor = conn.cursor()

    
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()

    cursor.close()
    conn.close()

    if users:
        return render_template('index.html', users=users)
    else:
        return jsonify({'message': 'No users found'})

# Add security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to every response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Add this to your database setup
def enhance_database_security():
    """Add security-related columns to the database"""
    conn = connect_db()
    cursor = conn.cursor()
    
    try:
        # Check if columns exist first
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add last_login_attempt column if it doesn't exist
        if 'last_login_attempt' not in columns:
            cursor.execute("""
                ALTER TABLE users ADD COLUMN 
                last_login_attempt TIMESTAMP
            """)
        
        # Add failed_login_attempts column if it doesn't exist
        if 'failed_login_attempts' not in columns:
            cursor.execute("""
                ALTER TABLE users ADD COLUMN 
                failed_login_attempts INTEGER DEFAULT 0
            """)
            
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database enhancement error: {str(e)}")
    finally:
        cursor.close()
        conn.close()

# Admin authentication decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_token = session.get('admin_token')
        if not admin_token or admin_token != ADMIN_PASSWORD:
            flash('Admin access required', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin login route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['admin_token'] = ADMIN_PASSWORD
            flash('Admin access granted', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin password', 'danger')
    return render_template('admin_login.html')

# Admin dashboard route
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = connect_db()
    cursor = conn.cursor()
    
    # Get database statistics
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE is_verified = 1")
    verified_count = cursor.fetchone()[0]
    
    cursor.close()
    conn.close()
    
    return render_template('admin_dashboard.html', 
                         user_count=user_count, 
                         verified_count=verified_count)

# Database reset route
@app.route('/admin/reset-database', methods=['POST'])
@admin_required
def reset_database():
    try:
        conn = connect_db()
        cursor = conn.cursor()
        
        # Delete all records from the users table
        cursor.execute("DELETE FROM users")
        
        # Reset the auto-increment counter
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='users'")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Clear all login attempts
        LOGIN_ATTEMPTS.clear()
        
        flash('Database has been reset successfully', 'success')
    except Exception as e:
        flash(f'Error resetting database: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.before_request
def before_request():
    """Check session timeout before each request"""
    if 'user' in session:
        # Check if last activity timestamp exists
        if 'last_activity' not in session:
            session.clear()
            flash("Session expired. Please login again.", "warning")
            return redirect(url_for('login'))
        
        # Check if session has expired (5 minutes of inactivity)
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now() - last_activity > timedelta(minutes=5):
            session.clear()
            flash("Session expired due to inactivity. Please login again.", "warning")
            return redirect(url_for('login'))
        
        # Update last activity timestamp
        session['last_activity'] = datetime.now().isoformat()

if __name__ == '__main__':
    setup_database()
    enhance_database_security()
    app.run(debug=False)  # Set debug to False in production