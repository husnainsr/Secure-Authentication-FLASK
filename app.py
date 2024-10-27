from flask import Flask, request, jsonify, render_template, redirect, url_for
import sqlite3
from datetime import datetime
import os
import bcrypt
from itsdangerous import URLSafeTimedSerializer
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart



app = Flask(__name__)
app.secret_key = 'qN7$k@4fX9b#4pR*3L2s&dZ9uH2m$eW' 

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
    password_hash = request.form['password']  # Normally, you'd hash the password here
    registration_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Capture current timestamp

    # Connect to the SQLite database
    conn = connect_db()
    cursor = conn.cursor()

    # Create users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            registration_date TEXT NOT NULL
        )
    ''')

    # Create sessions table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Insert new user into the 'users' table
    sql = "INSERT INTO users (username, email, password_hash, registration_date) VALUES (?, ?, ?, ?)"
    try:
        cursor.execute(sql, (username, email, password_hash, registration_date))
        user_id = cursor.lastrowid  # Get the ID of the newly inserted user
        conn.commit()  # Ensure data is committed to the database

        # Create a session for the newly registered user
        session_created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("INSERT INTO sessions (user_id, created_at) VALUES (?, ?)", (user_id, session_created_at))
        conn.commit()  # Ensure session data is committed to the database

        return jsonify({'message': 'User registered successfully!'})
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