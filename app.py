import os
from flask import Flask, render_template, request, redirect, session, flash, url_for
import qrcode
import uuid
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'quickmark'

def init_db():
    conn = sqlite3.connect('attendance.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attendance (
                    id TEXT, student_name TEXT, date TEXT, time TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS periods (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT NOT NULL,
                    date TEXT NOT NULL,
                    token TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    qr_code = None
    token = None
    if session.get('role') == 'teacher':
        conn = sqlite3.connect('attendance.db')
        c = conn.cursor()
        c.execute("SELECT token FROM periods ORDER BY id DESC LIMIT 1")
        result = c.fetchone()
        conn.close()
        if result:
            token = result[0]
            img = qrcode.make(token)
            img_path = os.path.join('static', 'qr.png')
            img.save(img_path)
            qr_code = img_path
    return render_template('index.html', qr_code=qr_code, token=token)

@app.route('/generate_qr')
def generate_qr():
    if session.get('role') != 'teacher':
        return redirect('/login')

    conn = sqlite3.connect('attendance.db')
    c = conn.cursor()
    c.execute("SELECT token FROM periods ORDER BY id DESC LIMIT 1")
    result = c.fetchone()
    conn.close()

    if not result:
        flash("No period created yet!")
        return redirect('/create_period')

    token = result[0]
    img = qrcode.make(token)
    img_path = os.path.join('static', 'qr.png')
    img.save(img_path)

    return redirect('/')

@app.route('/attendance')
def attendance():
    if session.get('role') != 'teacher':
        return redirect('/login')

    conn = sqlite3.connect('attendance.db')
    c = conn.cursor()
    c.execute("SELECT * FROM attendance")
    records = c.fetchall()
    conn.close()
    return render_template('attendance.html', records=records)

@app.route('/create_period', methods=['GET', 'POST'])
def create_period():
    if session.get('role') != 'teacher':
        return redirect('/login')

    if request.method == 'POST':
        subject = request.form['subject']
        date = request.form['date']
        token = str(uuid.uuid4())[:8]

        conn = sqlite3.connect('attendance.db')
        c = conn.cursor()
        c.execute("INSERT INTO periods (subject, date, token) VALUES (?, ?, ?)", (subject, date, token))
        conn.commit()
        conn.close()

        flash(f'Period created. Token: {token}')
        return redirect('/')

    return render_template('create_period.html')

@app.route('/scan')
def scan():
    if session.get('role') != 'student':
        return redirect('/login')
    return render_template('scan.html')

@app.route('/mark_attendance', methods=['POST'])
def mark_attendance():
    student_name = request.form['name']
    session_id = request.form['session_id']
    now = datetime.now()
    conn = sqlite3.connect('attendance.db')
    c = conn.cursor()
    c.execute("INSERT INTO attendance VALUES (?, ?, ?, ?)",
              (session_id, student_name, now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S")))
    conn.commit()
    conn.close()
    return "Attendance Marked"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        conn = sqlite3.connect('attendance.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
            conn.commit()
            flash('Registration successful. Please login.')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('Username already exists.')
        conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('attendance.db')
        c = conn.cursor()
        c.execute("SELECT password, role FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[0], password):
            session['username'] = username
            session['role'] = user[1]
            return redirect('/dashboard')
        flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    if session['role'] == 'teacher':
        return redirect('/')
    elif session['role'] == 'student':
        return redirect('/scan')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=False, use_reloader=False)
