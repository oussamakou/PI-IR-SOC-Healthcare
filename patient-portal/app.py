from flask import Flask, render_template, request, redirect, url_for, flash
import logging
import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Configure logging for SOC monitoring
logging.basicConfig(filename='portal.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/')
def index():
    logging.info(f"Page View: Index - IP: {request.remote_addr}")
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Log login attempt
        logging.info(f"Login Attempt - User: {username} - IP: {request.remote_addr}")
        
        if username == 'admin' and password == 'password':
            logging.warning(f"Login Success: Admin User - IP: {request.remote_addr}")
            return redirect(url_for('dashboard'))
        elif username == 'patient' and password == 'patient':
            logging.info(f"Login Success: Patient User - IP: {request.remote_addr}")
            return redirect(url_for('dashboard'))
        else:
            logging.error(f"Login Failed - User: {username} - IP: {request.remote_addr}")
            flash('Invalid Credentials')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    logging.info(f"Page View: Dashboard - IP: {request.remote_addr}")
    return render_template('dashboard.html')

@app.route('/appointment', methods=['POST'])
def appointment():
    date = request.form.get('date')
    reason = request.form.get('reason')
    logging.info(f"Appointment Scheduled - Date: {date} - Reason: {reason} - IP: {request.remote_addr}")
    return "Appointment Scheduled"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
