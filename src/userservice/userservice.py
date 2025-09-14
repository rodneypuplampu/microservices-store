import sqlite3
import hashlib
import os
from flask import Flask, request, jsonify, g

# --- App Configuration ---
DATABASE_NAME = 'user_profiles.db'

app = Flask(__name__)

# --- Database Functions ---

def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE_NAME)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'db'):
        g.db.close()

def setup_database():
    """Sets up the SQLite database and 'users' table if it doesn't exist."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        db.commit()
        print("Database is set up and ready.")

# --- Password Hashing Functions ---

def hash_password(password):
    """Hashes the password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, provided_password):
    """Verifies if the provided password matches the stored hash."""
    return stored_hash == hash_password(provided_password)

# --- API Endpoints ---

@app.route('/register', methods=['POST'])
def register_user():
    """
    Handles user registration via a POST request.
    Expects a JSON payload with 'username' and 'password'.
    """
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing username or password'}), 400

    username = data['username']
    password = data['password']
    password_hash = hash_password(password)
    db = get_db()

    try:
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        db.commit()
        return jsonify({'message': f"User '{username}' registered successfully!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f"Username '{username}' already exists."}), 409
    except sqlite3.Error as e:
        return jsonify({'error': f"A database error occurred: {e}"}), 500


@app.route('/login', methods=['POST'])
def login_user():
    """
    Handles user login via a POST request.
    Expects a JSON payload with 'username' and 'password'.
    """
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing username or password'}), 400

    username = data['username']
    password = data['password']
    db = get_db()
    
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if user and verify_password(user['password_hash'], password):
        # In a real microservice, you would return a session token (JWT) here.
        # For simplicity, we'll just return a success message.
        return jsonify({'message': f"Login successful for user '{username}'."}), 200
    else:
        return jsonify({'error': 'Invalid username or password.'}), 401

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Kubernetes."""
    return jsonify({'status': 'ok'}), 200


if __name__ == '__main__':
    # Set up the database if the file doesn't exist
    if not os.path.exists(DATABASE_NAME):
        print(f"Database '{DATABASE_NAME}' not found. Creating it now.")
        setup_database()
    
    # Run the Flask application
    # In a real deployment, this is run by a WSGI server like Gunicorn.
    app.run(host='0.0.0.0', port=5000, debug=True)
