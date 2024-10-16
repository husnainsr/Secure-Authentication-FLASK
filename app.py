# from flask import Flask, render_template, request, redirect, url_for, jsonify
# import sqlite3
# import os
# from datetime import datetime

# app = Flask(__name__)

# # Configure SQLite database path
# DATABASE = 'db.db'

# # Function to connect to the database
# def get_db_connection():
#     conn = sqlite3.connect(DATABASE)
#     conn.row_factory = sqlite3.Row  # To return rows as dictionaries
#     return conn

# # Example route to show database connectivity
# @app.route('/')
# def index():
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")  # Show available tables
#     tables = cursor.fetchall()
#     conn.close()
#     return render_template('index.html', tables=tables)

# if __name__ == '__main__':
#     app.run(debug=True)


from flask import Flask, request, jsonify, render_template
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)

# Set the absolute path to your SQLite database on the desktop
DB_PATH = os.path.join(os.path.expanduser('~'), 'Desktop', 'secure_auth.db')

# Function to connect to SQLite Database
def connect_db():
    # Connect to the database stored on the desktop
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row  # Enable dictionary-like access to rows
    return connection

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

if __name__ == '__main__':
    app.run(debug=True)