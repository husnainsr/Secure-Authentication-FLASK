from flask import Flask, request, jsonify, render_template, redirect, url_for
import sqlite3
from datetime import datetime
import os
import bcrypt
from itsdangerous import URLSafeTimedSerializer
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

s = URLSafeTimedSerializer(app.secret_key)

# Set the absolute path to your SQLite database on the desktop
DB_PATH = os.path.join(os.path.expanduser('~'), 'Desktop', 'secure_auth.db')

# Function to connect to SQLite Database
def connect_db():
    # Connect to the database stored on the desktop
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row  # Enable dictionary-like access to rows
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
            is_verified INTEGER DEFAULT 0
        )
    ''')

    # Check if the is_verified column exists, if not add it
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'is_verified' not in columns:
        cursor.execute('ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0;')

    conn.commit()
    cursor.close()
    conn.close()


# Route to render registration form
@app.route('/')
def index():
    return render_template('register.html')

def send_verification_email(email, token):
    sender_email = "djbravochamp817@gmail.com"
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
            server.login(sender_email, "kwih hngn jlbm njdt")  # Replace with actual email and password
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
    password = request.form['password']  # Normally, you'd hash the password here
    registration_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Capture current timestamp
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    setup_database()  # Ensure the database is set up before registering a user

    conn = connect_db()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, email, password_hash, registration_date) VALUES (?, ?, ?, ?)", 
                       (username, email, hashed_password, registration_date))
        conn.commit()

        token = s.dumps(email, salt='email-confirm')
        print(f"Token generated: {token}")  # Debug print
        send_verification_email(email, token)

        return render_template('register.html', message="Registration successful! Please check your email to verify your account.")
    except sqlite3.Error as e:
        return jsonify({'error': str(e)})
    finally:
        cursor.close()
        conn.close()


@app.route('/verify/<token>')
def verify_email(token):
    try:
        # Set max_age to None to disable expiration
        email = s.loads(token, salt='email-confirm', max_age=None)  
        print(f"Token valid. Email: {email}")  # Debug print
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
        conn.commit()

        return render_template('verify.html', message="Email verified successfully! You may now log in.")
    except Exception as e:
        print(f"Error verifying token: {e}")  # Debug print
        return render_template('verify.html', message="Verification link expired or invalid. Please register again.")
    
    

@app.route('/show_all_users', methods=['GET'])
def show_all_users():
    conn = connect_db()
    cursor = conn.cursor()

    # Fetch all users from the 'users' table
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