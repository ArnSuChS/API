from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import hashlib
import pyotp
from datetime import datetime, timedelta
import qrcode
import io
import base64
from kiteconnect import KiteConnect
from flask import request, abort

app = Flask(__name__)
app.secret_key = 'your_secret_key'

API_KEY = "your_api_key"
API_SECRET = "your_api_secret"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = hash_password(password)

        secret = pyotp.random_base32()  

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password, secret, otp_created_at) VALUES (?, ?, ?, ?)',
                         (username, hashed, secret, datetime.now()))
            conn.commit()
        except sqlite3.IntegrityError:
            return 'Username already exists'
        finally:
            conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = hash_password(password)

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username=? AND password=?',
                            (username, hashed)).fetchone()
        conn.close()

        if user:
            session['temp_user'] = username  
            return redirect(url_for('verify'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'temp_user' not in session:
        return redirect(url_for('login'))

    username = session['temp_user']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    conn.close()

    secret = user['secret']
    totp = pyotp.TOTP(secret)

    current_code = totp.now()

    provisioning_uri = totp.provisioning_uri(name=username, issuer_name="MyWebsite")
    qr = qrcode.make(provisioning_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    if request.method == 'POST':
        code = request.form['code']
        if totp.verify(code):
            session['username'] = username
            session.pop('temp_user', None)
            return redirect(url_for('index'))
        else:
            return 'Invalid code'

    return render_template('verify.html', secret=secret, qr_code=qr_base64, code=current_code)

@app.route('/kite_login')
def kite_login():
    kite = KiteConnect(api_key=API_KEY)
    login_url = kite.login_url()
    return redirect(login_url)

@app.route('/kite_profile')
def kite_profile():
    if "kite_access_token" not in session:
        return redirect(url_for('kite_login'))

    kite = KiteConnect(api_key=API_KEY)
    kite.set_access_token(session["kite_access_token"])

    try:
        profile = kite.profile()
        return jsonify(profile)
    except Exception as e:
        return f"Error fetching profile: {str(e)}"

@app.route('/kite_callback')
def kite_callback():
    request_token = request.args.get("request_token")
    if not request_token:
        return render_template('kite_callback.html', error="No request_token received.")

    kite = KiteConnect(api_key=API_KEY)
    try:
        data = kite.generate_session(request_token, api_secret=API_SECRET)
        access_token = data["access_token"]

        session["kite_access_token"] = access_token
        session["kite_user_name"] = data["user_name"]

        return render_template("kite_callback.html", user=data["user_name"], token=access_token)
    except Exception as e:
        return render_template("kite_callback.html", error=str(e))

@app.route('/kite_postback', methods=['POST'])
def kite_postback():
    data = request.get_json()

    if not data:
        abort(400, 'Invalid data')

    print("Received Postback:", data)

    with open("postback_log.txt", "a") as f:
        f.write(str(data) + "\n")

    return "Postback received", 200

##@app.route('/api/generate_code', methods=['GET'])
##def generate_code():
##    if 'username' not in session:
##        return jsonify({'error': 'Unauthorized'}), 401
##
##    conn = get_db_connection()
##    user = conn.execute('SELECT * FROM users WHERE username=?', (session['username'],)).fetchone()
##    conn.close()
##
##    totp = pyotp.TOTP(user['secret'])
##    code = totp.now()
##    return jsonify({'code': code})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
