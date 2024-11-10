from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
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

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

s = URLSafeTimedSerializer(app.secret_key)
DB_PATH = os.path.join(os.path.expanduser('~'), 'Desktop', 'secure_auth.db')

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


def send_verification_email(email, token):
    sender_email = os.getenv("EMAIL")
    receiver_email = email
    subject = "Please confirm your email"
    link = url_for('verify_email', token=token, _external=True)

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    text = f"Hi,\n\nPlease click the following link to verify your email address:\n{link}\n\nThank you!"
    message.attach(MIMEText(text, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            PASSWORD=os.getenv("PASSWORD")
            server.login(sender_email, PASSWORD)  
            server.sendmail(sender_email, receiver_email, message.as_string())
            print("Email sent successfully.")
    except smtplib.SMTPException as e:
        print(f"SMTP error occurred: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Route to register a new user and insert into the database
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']  
    registration_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  

    # Password Requirenments
    if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'\d', password):
        flash("Password must be at least 8 characters, contain uppercase and lowercase letters, and include a number.", "danger")
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

    setup_database()  # Ensure the database is set up before registering a user

    conn = connect_db()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, email, password_hash, registration_date) VALUES (?, ?, ?, ?)", 
                       (username, email, hashed_password, registration_date))
        conn.commit()
        
        token = s.dumps(email, salt='email-confirm')
        print(f"Token generated: {token}")  
        send_verification_email(email, token)
        flash("Registration successful! Please check your email to verify your account.", "info")
        return render_template('register.html', message="Registration successful! Please check your email to verify your account.")
    except sqlite3.Error as e:
        return jsonify({'error': str(e)})
    finally:
        cursor.close()
        conn.close()


@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=None)  
        print(f"Token valid. Email: {email}")  
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
        conn.commit()

        return render_template('verify.html', message="Email verified successfully! You may now log in.")
    except Exception as e:
        print(f"Error verifying token: {e}")  
        return render_template('verify.html', message="Verification link expired or invalid. Please register again.")
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login and initiate OTP process. Implemented by Khadijah and Husnain."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            if not user['is_verified']:
                flash("Please verify your email before logging in.", "warning")
                return redirect(url_for('login'))
            
            # Husnain – OTP Generation
            otp = generate_otp()
            otp_expiration = datetime.now() + timedelta(minutes=5)
            otp_expiration_str = otp_expiration.strftime('%Y-%m-%d %H:%M:%S')

            flash("An OTP has been sent to your email. Please enter it below.", "info")
            return redirect(url_for('verify_otp'))
        else:
            flash("Invalid email or password.", "danger")
            return render_template('login.html')

    return render_template('login.html')


@app.route('/welcome')
def welcome():
    return render_template('welcome.html')


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




if __name__ == '__main__':
    app.run(debug=True)