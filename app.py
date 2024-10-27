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

        return render_template('register.html', message="Registration successful! Please check your email to verify your account.")
    except sqlite3.Error as e:
        return jsonify({'error': str(e)})
    finally:
        cursor.close()
        conn.close()


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