from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

# Configure SQLite database path
DATABASE = 'db.db'

# Function to connect to the database
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # To return rows as dictionaries
    return conn

# Example route to show database connectivity
@app.route('/')
def index():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")  # Show available tables
    tables = cursor.fetchall()
    conn.close()
    return render_template('index.html', tables=tables)

if __name__ == '__main__':
    app.run(debug=True)
