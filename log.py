import sqlite3
import re
from flask import Flask, render_template, request, redirect, url_for, flash,session ,Response,jsonify,make_response
from md5 import *
from sha import *
import random 
from block import *
from datetime import datetime, timezone, timedelta
from db import *
import smtplib
import random
from email.message import EmailMessage
import time

app = Flask(__name__)
app.secret_key = 'your_secret_key' 

# Function to validate email domain

@app.route('/')
def home():
    error_message = session.pop('error_message', None)
    return render_template('login.html', error_message=error_message)


@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        conn = sqlite3.connect('user_credentials.db')
        cursor = conn.cursor()

        email = request.form['email']
        password = request.form['password']

        if not validate_email_domain(email):
            return '''
                <script>
                    alert("Email should belong to the domain @gmail.com");
                    window.location.replace("/");
                </script>
            '''
            
        if not 8 <= len(password) <= 16:
            return '''
                <script>
                    alert("Password length should be between 8 and 16 characters");
                    window.location.replace("/");
                </script>
            '''
        
        password = message_hash(password)
        cursor.execute('SELECT username FROM users WHERE email = ? AND password = ?', (email, password))
        user = cursor.fetchone()

        if user:
            session['login_attempts'] = 0
            return f'''
        <script>
            alert("Welcome, {user[0]}! Logged in successfully");
            window.location.replace("{url_for('pinaf', username=user)}");
        </script>
    '''

        else:
            if 'login_attempts' not in session:
                session['login_attempts'] = 0

            session['login_attempts'] += 1
            if session['login_attempts'] < 3:
                attempts_left = 3 - session['login_attempts']
                return f'''
                    <script>
                        alert("Invalid email or password. You have {attempts_left} attempts left");
                        window.location.replace("/");
                    </script>
                '''
            else:
                return '''
                    <script>
                        alert("Invalid email or password. You are locked out. Please try again later");
                        window.location.replace("/");
                    </script>
                '''
@app.route('/register', methods=['POST'])
def register():
        conn = sqlite3.connect('user_credentials.db')
        cursor = conn.cursor()

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if not validate_email_domain(email):
            return '''
                <script>
                    alert("Email should belong to the domain @crypto.com");
                    window.location.replace("/register");
                </script>
            '''
            
        if not 8 <= len(password) <= 16:
            return '''
                <script>
                    alert("Password length should be between 8 and 16 characters");
                    window.location.replace("/");
                </script>
            '''

        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        password = message_hash(password)
        
        if user:
            return '''
            <script>
                alert("User already exists");
                window.location.replace("/");
            </script>
            '''
        else:
            random_amount = random.randint(2000, 10000)
            cursor.execute('INSERT INTO users (username, email, password, amount) VALUES (?, ?, ?, ?)', 
                           (username, email, password, random_amount))
            conn.commit()
            conn.close()
        return redirect(url_for('pin', username=username))

@app.route('/pin')
def pin():
    username = request.args.get('username')
    session['username'] = username
    return render_template('pin.html', username=username)

@app.route('/pinaf')
def pinaf():
    username = request.args.get('username')
    session['username'] = username
    return render_template('pinaf.html', username=username)

@app.route('/submit_pin', methods=['POST'])
def submit_pin():
    if request.method == 'POST':
        username = session.get('username')
        pin = request.form['pin']
        confirmed_pin = request.form['confirmPassword']
        
        if len(pin) < 6 or len(confirmed_pin) < 6:
            alert_message = '''
                <script>
                    alert("PIN length should be at least 6 characters");
                    window.location.replace("/pin?username={}");
                </script>
            '''.format(username)
            return alert_message

        if pin == confirmed_pin:
            confirmed_pin += username 
            confirmed_pin = pinhash(confirmed_pin)
            conn = sqlite3.connect('user_credentials.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET pin = ? WHERE username = ?', (confirmed_pin, username))
            conn.commit()
            conn.close()
            # flash('Pin set successfully! Please log in to access your account.','success')
            '''<script>
                alert("Pin set sucessfully");
            </script>
            '''
            return redirect(url_for('pinaf',username=username))

        elif pin != confirmed_pin:
            alert_message = '''
        <script>
            alert("Pin doesn't Match");
            window.location.replace("/pin",username=username);
        </script>
    '''
            return alert_message
        
    return "Invalid request method"

# @app.route('/logout', methods=['POST'])
# def logout():
#     if request.method == 'POST':
#         session.clear()
#         return redirect(url_for('home'), code=307)

@app.route('/logout', methods=['POST'])
def logout():
    if request.method == 'POST':
        session.clear()
        response = make_response(redirect(url_for('home')))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    


@app.route('/thank')
def thank():
    username = session.get('username')  
    return render_template('thank.html', username=username)


@app.route('/get_usernames', methods=['GET'])
def get_usernames():
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()

    cursor.execute('SELECT username FROM users')
    usernames = cursor.fetchall()

    conn.close()

    return {'usernames': usernames}

@app.route('/get_balance', methods=['GET'])
def get_balance():
    if 'username' in session:
        username = session['username']
        conn = sqlite3.connect('user_credentials.db')
        cursor = conn.cursor()
        cursor.execute('SELECT amount FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            return {'balance': user[0]}

    return {'balance': 'Not available'}

@app.route('/transfer', methods=['GET','POST'])
def transfer():
    if 'username' in session:
        username = session['username']
        conn = sqlite3.connect('user_credentials.db')
        cursor = conn.cursor()

        # Fetch all users except the logged-in user
        cursor.execute('SELECT username FROM users WHERE username != ?', (username,))
        users = cursor.fetchall()

        conn.close()

        return render_template('transfer.html', username=username, users=users)
    else:
        return redirect(url_for('home'))


# Transfer funds route
@app.route('/transfer_funds', methods=['POST'])
def transfer_funds():
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()

    if 'username' in session:
        username = session['username']
        selected_user = request.form['selected_user']
        amount = int(request.form['amount'])
        pin = request.form['pin']
        cursor.execute('SELECT email, amount, pin FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        sender_email = row[0]
        sender_balance = row[1]
        user_pin = row[2]

        if len(pin) != 6:
            flash("Pin must be 6 Digits", 'error')
            return redirect(url_for('home'))

        # Check if PIN is correct
        pin_attempt = pin + username
        pin_attempt_hash = str(pinhash(pin_attempt))
        if pin_attempt_hash != user_pin:
            flash("Enter Correct Pin", 'error')
            return redirect(url_for('pinaf', username=session['username']))

        # Check if sender has sufficient balance
        if sender_balance < amount + 2000:  # Considering a minimum balance of 2000
            flash("Insufficient Balance to send Funds", 'error')
            return redirect(url_for('home'))

        # Store necessary information in session for OTP verification
        session['transfer_details'] = {
            'sender_email': sender_email,
            'amount': amount,
            'selected_user': selected_user
        }

        # Generate and send OTP
        otp = generate_otp()
        send_otp(sender_email, otp)
        session['otp'] = otp  # Store OTP in session for verification

        # Close database connection
        conn.close()

        # Redirect to OTP verification page
        return redirect(url_for('index'))

    else:
        flash('User session not found', 'error')
        conn.close()
        return redirect(url_for('home'))

@app.route('/index')
def index():
    return render_template('verify.html')


@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if 'transfer_details' not in session:
        return redirect(url_for('home'))  # Redirect if transfer details are not stored in session

    transfer_details = session['transfer_details']
    sender_email = transfer_details['sender_email']
    amount = transfer_details['amount']
    selected_user = transfer_details['selected_user']

    input_otp = request.form['otp']
    actual_otp = session['otp']

    if input_otp == actual_otp:
        # Perform debit operation
        conn = sqlite3.connect('user_credentials.db')
        cursor = conn.cursor()

        # Update sender's balance
        cursor.execute('UPDATE users SET amount = amount - ? WHERE username = ?', (amount, session['username']))

        # Update recipient's balance
        cursor.execute('UPDATE users SET amount = amount + ? WHERE username = ?', (amount, selected_user))

        # Fetch sender's email for transaction record
        cursor.execute('SELECT email FROM users WHERE username = ?', (session['username'],))
        sender_email = cursor.fetchone()[0]

        # Inserting transaction details into transfer_details.db
        conn_transfer = sqlite3.connect('transfer_details.db')
        cursor_transfer = conn_transfer.cursor()

        # Check if the transfer_records table is empty or not
        cursor_transfer.execute('SELECT COUNT(*) FROM transfer_records')
        count = cursor_transfer.fetchone()[0]

        ist_now = get_indian_time()
        date = time.time()
        info = f"{session['username']} sending {amount} to {selected_user}"
       
        if count == 0:
            previous_hash = pinhash(str(info) + str(date) + str(0))
            hash_value = previous_hash
            nonce, modified_hash = mine(hash_value)

            cursor_transfer.execute('''INSERT INTO transfer_records 
                                    (users_name, users_email, recipients_username, timestamp, amount, previous_hash, hash, nonce, modified_hash) 
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                    (session['username'], sender_email, selected_user, ist_now, amount, previous_hash, hash_value, nonce, modified_hash))
            
        else:
            cursor_transfer.execute('SELECT modified_hash FROM transfer_records ORDER BY id DESC LIMIT 1')
            previous_hash = cursor_transfer.fetchone()[0]
            hash_value = pinhash(str(info) + str(date) + str(previous_hash))
            nonce, modified_hash = mine(hash_value)
            cursor_transfer.execute('''INSERT INTO transfer_records 
                                    (users_name, users_email, recipients_username, timestamp, amount, previous_hash, hash, nonce, modified_hash) 
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                    (session['username'], sender_email, selected_user, ist_now, amount, previous_hash, hash_value, nonce, modified_hash))

        conn_transfer.commit()
        conn_transfer.close()
        conn.commit()
        conn.close()
        
        session.pop('transfer_details', None)  # Remove transfer details from session
        session.pop('otp', None)  # Remove OTP from session after successful verification
        flash("Transfer successful. Redirecting to your e-commerce account.")

        # Redirect to e-commerce logged-in page
        e_commerce_logged_in_url = "http://localhost/projectdone/orders.php"  # Replace with actual e-commerce URL
        return redirect(e_commerce_logged_in_url)
    else:
        flash("Invalid OTP", 'error')
        return redirect(url_for('transfer'))  # Redirect back to transfer page for re-entering OTP

# Existing routes and functions from code 2...
# Generate OTP function
def generate_otp():
    otp = ""
    for i in range(6):
        otp += str(random.randint(0, 9))
    return otp

# Send OTP function
def send_otp(email, otp):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    from_mail = 'ambatisaisindhur@gmail.com'  # Update with your email
    server.login(from_mail, 'wwst wzbn fjgv yehv')  # Update with your password
    msg = EmailMessage()
    msg['Subject'] = "OTP Verification"
    msg['From'] = from_mail
    msg['To'] = email
    msg.set_content("Your OTP is: " + otp)
    server.send_message(msg)
    server.quit()

@app.route('/get_last_transaction', methods=['GET'])
def get_last_transaction():
    if 'username' in session:
        username = session['username']
        conn_transfer = sqlite3.connect('transfer_details.db')
        cursor_transfer = conn_transfer.cursor()

        # Modify the query to fetch transactions for a specific user
        cursor_transfer.execute('SELECT * FROM transfer_records WHERE users_name = ? ORDER BY id DESC LIMIT 1', (username,))
        last_transaction = cursor_transfer.fetchone()

        conn_transfer.close()

        if last_transaction:
            transaction = {
                'id': last_transaction[0],
                'users_name': last_transaction[1],
                'users_email': last_transaction[2],
                'recipients_username': last_transaction[3],
                'timestamp': last_transaction[4],
                'amount': last_transaction[5],
                'previous_hash': last_transaction[6],
                'hash': last_transaction[7],
                'nonce': last_transaction[8],
                'modified_hash': last_transaction[9]
            }
            return jsonify(transaction)
        else:
            return jsonify('No transactions found for this user')
    else:
        return jsonify({'error': 'User not logged in'})
    
# if __name__ == '__main__':
#     app.run(debug=True)
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)