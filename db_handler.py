import sqlite3
from datetime import datetime, timedelta
import os
from werkzeug.security import generate_password_hash, check_password_hash

# --- DB Config ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, 'todo.db')

# --- Initialization ---
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS progress (
                user_id INTEGER,
                day INTEGER,
                date TEXT,
                completed INTEGER DEFAULT 0,
                PRIMARY KEY (user_id, day),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        conn.commit()

# --- User Management ---
def get_user_by_username(username):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        return c.fetchone()

def create_user(username, password, is_admin=0):
    hashed_password = generate_password_hash(password)
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                  (username, hashed_password, is_admin))
        conn.commit()
        return c.lastrowid

def validate_login(username, password):
    user = get_user_by_username(username)
    if user and check_password_hash(user[2], password):
        return user
    return None

def is_admin(user_id):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
        row = c.fetchone()
        return row and row[0] == 1

# --- Progress Tracking ---
def create_user_progress(user_id):
    today = datetime.today()
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        for i in range(250):
            day_date = today + timedelta(days=i)
            c.execute('INSERT OR IGNORE INTO progress (user_id, day, date) VALUES (?, ?, ?)',
                      (user_id, i + 1, day_date.strftime('%Y-%m-%d')))
        conn.commit()

def get_user_progress(user_id, as_dict=False):
    with sqlite3.connect(DB_NAME) as conn:
        if as_dict:
            conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM progress WHERE user_id = ? ORDER BY day ASC', (user_id,))
        rows = c.fetchall()
        return [dict(row) for row in rows] if as_dict else rows

def update_day(user_id, day):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('UPDATE progress SET completed = 1 WHERE user_id = ? AND day = ?', (user_id, day))
        conn.commit()

# --- Admin Controls ---
def get_all_users_with_progress():
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT u.id, u.username, u.password, u.is_admin,
                   COUNT(p.day) AS total_tasks,
                   SUM(p.completed) AS completed_tasks
            FROM users u
            LEFT JOIN progress p ON u.id = p.user_id
            GROUP BY u.id
        ''')  # Removed the "#" comment from the SQL string
        return [dict(row) for row in c.fetchall()]

def complete_all_tasks_for_user(user_id):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('UPDATE progress SET completed = 1 WHERE user_id = ?', (user_id,))
        conn.commit()

def reset_all_tasks_for_user(user_id):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('UPDATE progress SET completed = 0 WHERE user_id = ?', (user_id,))
        conn.commit()

# --- Utility ---
def phase_unlocked(progress, phase):
    def is_completed(day):
        return day['completed'] if isinstance(day, dict) else day[3]

    if phase == 1:
        return True
    if phase == 2:
        return all(is_completed(day) for day in progress if 1 <= (day['day'] if isinstance(day, dict) else day[1]) <= 100)
    if phase == 3:
        return all(is_completed(day) for day in progress if 101 <= (day['day'] if isinstance(day, dict) else day[1]) <= 200)
    return False
