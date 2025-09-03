from flask import Flask, render_template, redirect, url_for, request, session, flash
from db_handler import (
    init_db, create_user, get_user_by_username,
    create_user_progress, get_user_progress,
    update_day, phase_unlocked, DB_NAME, get_all_users_with_progress  # Add this
)

from db_handler import validate_login
import sqlite3

app = Flask(__name__)
app.secret_key = 'supersecretkey'


# -------------------- ADMIN HELPERS --------------------

def is_admin(user_id):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
        result = c.fetchone()
        return result and result[0] == 1



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


# -------------------- ROUTES --------------------

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    progress = get_user_progress(user_id)
    is_admin_user = is_admin(user_id)  # check admin status

    return render_template('index.html', progress=progress, unlocked_phases={
        1: phase_unlocked(progress, 1),
        2: phase_unlocked(progress, 2),
        3: phase_unlocked(progress, 3)
    }, is_admin=is_admin_user)  # pass to template


@app.route('/complete/<int:day>', methods=['POST'])
def complete(day):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    update_day(session['user_id'], day)
    return redirect(url_for('index'))


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username'].strip()
#         password = request.form['password'].strip()
#         user = get_user_by_username(username)
#         if user and user[2] == password:
#             session['user_id'] = user[0]
#             create_user_progress(user[0])
#             return redirect(url_for('index'))
#         flash('Invalid credentials')
#     return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        user = validate_login(username, password)
        if user:
            session['user_id'] = user[0]
            create_user_progress(user[0])
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        is_admin_flag = 1 if 'is_admin' in request.form else 0

        if get_user_by_username(username):
            flash('Username already exists')
        else:
            user_id = create_user(username, password, is_admin_flag)
            create_user_progress(user_id)
            session['user_id'] = user_id
            return redirect(url_for('index'))
    return render_template('signup.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# -------------------- ADMIN ROUTES --------------------

@app.route('/admin')
def admin():
    if 'user_id' not in session or not is_admin(session['user_id']):
        return "Unauthorized", 403
    try:
        users = get_all_users_with_progress()
        print("First user in list:", users[0])  # For debug
    except Exception as e:
        print("Error in get_all_users_with_progress:", e)
        return "Internal Server Error", 500
    return render_template('admin.html', users=users)


@app.route('/admin/complete/<int:user_id>')
def admin_complete_user(user_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        return "Unauthorized", 403
    complete_all_tasks_for_user(user_id)
    return redirect(url_for('admin'))


@app.route('/admin/reset/<int:user_id>')
def admin_reset_user(user_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        return "Unauthorized", 403
    reset_all_tasks_for_user(user_id)
    return redirect(url_for('admin'))


@app.route('/admin/delete/<int:user_id>')
def admin_delete_user(user_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        return "Unauthorized", 403

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM progress WHERE user_id = ?', (user_id,))
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    return redirect(url_for('admin'))


# -------------------- DEV SHORTCUT --------------------

@app.route('/dev/complete_next_phase')
def complete_next_phase():
    if not app.debug or 'user_id' not in session:
        return "Unauthorized", 403

    phase_ranges = {
        1: (1, 100),
        2: (101, 200),
        3: (201, 250),
    }

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        for phase, (start, end) in phase_ranges.items():
            c.execute('SELECT COUNT(*) FROM progress WHERE user_id = ? AND day BETWEEN ? AND ? AND completed = 0',
                      (session['user_id'], start, end))
            if c.fetchone()[0] > 0:
                c.execute('UPDATE progress SET completed = 1 WHERE user_id = ? AND day BETWEEN ? AND ?',
                          (session['user_id'], start, end))
                conn.commit()
                return f"✅ Phase {phase} marked as completed."
    return "🎉 All phases already completed!"


# -------------------- INIT APP --------------------

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
