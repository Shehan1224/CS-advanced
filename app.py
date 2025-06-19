from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import numpy as np
import pandas as pd
from colorama import Fore, Back, Style, init
from termcolor import colored
import pyfiglet
import requests
import json
import time
from scipy.signal import argrelextrema
from sklearn.ensemble import RandomForestClassifier
from textblob import TextBlob
import nltk
from nltk.sentiment.vader import SentimentIntensityAnalyzer
import threading
import uuid
from datetime import datetime
from td_new import get_crypto_data, calculate_indicators, identify_liquidity_zones, calculate_fibonacci_levels, generate_signals

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Login credentials
USERNAME = 'shehan'
PASSWORD = 'password'

# Admin credentials for session management
ADMIN_USERNAME = 'Shehan'
ADMIN_PASSWORD = 'Chamudi@1224*%'

# Active sessions and blocked devices
active_sessions = {}
blocked_devices = set()
invalidated_sessions = set()  # Track invalidated sessions
admin_settings = {
    'password': ADMIN_PASSWORD
}

# Initialize NLTK and sentiment analyzer
nltk.download('vader_lexicon')
sia = SentimentIntensityAnalyzer()


# Initialize AI model
class AIConfirmation:

    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100)
        self.trained = False

    def train_model(self, X, y):
        self.model.fit(X, y)
        self.trained = True

    def predict_signal(self, features):
        if not self.trained:
            return 0.5  # Neutral if not trained
        proba = self.model.predict_proba([features])[0]
        return proba[1]  # Probability of positive signal


ai_model = AIConfirmation()

# Login required decorator
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        
        # Check if session has been invalidated by admin
        session_id = session.get('session_id')
        if session_id and session_id in invalidated_sessions:
            session.clear()
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Admin authentication decorator
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# All your existing functions from td_new.py go here...
# (get_crypto_data, calculate_rsi, calculate_macd, etc.)
# ... up to the display_results function


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Get device identifier
    device_id = request.headers.get('User-Agent', '') + request.remote_addr
    device_hash = str(hash(device_id))
    
    # Check if device is blocked
    if device_hash in blocked_devices:
        return render_template('login.html', error='This device has been blocked')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == USERNAME and password == PASSWORD:
            session_id = str(uuid.uuid4())
            session['logged_in'] = True
            session['session_id'] = session_id
            session['device_hash'] = device_hash
            
            # Store active session
            active_sessions[session_id] = {
                'device_hash': device_hash,
                'login_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'Unknown')
            }
            
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session_id = session.get('session_id')
    if session_id:
        if session_id in active_sessions:
            del active_sessions[session_id]
        # Clean up from invalidated sessions if present
        invalidated_sessions.discard(session_id)
    
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    # Check if user is logged in to main site first
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == ADMIN_USERNAME and password == admin_settings['password']:
            session['admin_logged_in'] = True
            return redirect(url_for('manage_sessions'))
        else:
            return render_template('admin_login.html', error='Invalid admin credentials')
    
    return render_template('admin_login.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/manage_sessions')
@admin_required
def manage_sessions():
    return render_template('manage_sessions.html', sessions=active_sessions, blocked_devices=blocked_devices)

@app.route('/logout_session/<session_id>')
@admin_required
def logout_session(session_id):
    if session_id in active_sessions:
        # Add to invalidated sessions to force logout
        invalidated_sessions.add(session_id)
        del active_sessions[session_id]
    return redirect(url_for('manage_sessions'))

@app.route('/block_device/<device_hash>')
@admin_required
def block_device(device_hash):
    blocked_devices.add(device_hash)
    # Remove all sessions from this device and invalidate them
    sessions_to_remove = [sid for sid, data in active_sessions.items() if data['device_hash'] == device_hash]
    for sid in sessions_to_remove:
        invalidated_sessions.add(sid)  # Force session invalidation
        del active_sessions[sid]
    return redirect(url_for('manage_sessions'))

@app.route('/unblock_device/<device_hash>')
@admin_required
def unblock_device(device_hash):
    blocked_devices.discard(device_hash)
    return redirect(url_for('manage_sessions'))

@app.route('/change_admin_password', methods=['GET', 'POST'])
@admin_required
def change_admin_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if current_password != admin_settings['password']:
            flash('Current password is incorrect', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'error')
        elif len(new_password) < 6:
            flash('New password must be at least 6 characters', 'error')
        else:
            admin_settings['password'] = new_password
            flash('Password changed successfully', 'success')
            return redirect(url_for('manage_sessions'))
    
    return render_template('change_admin_password.html')

@app.route('/force_logout_user/<session_id>')
@admin_required
def force_logout_user(session_id):
    if session_id in active_sessions:
        device_hash = active_sessions[session_id]['device_hash']
        # Block device temporarily and remove session
        blocked_devices.add(device_hash)
        invalidated_sessions.add(session_id)  # Force session invalidation
        del active_sessions[session_id]
        flash(f'User has been logged out and device temporarily blocked', 'success')
    return redirect(url_for('manage_sessions'))


@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    if request.method == 'GET':
        # Handle GET request from View Details button
        symbol = request.args.get('symbol', '').upper()
        interval = request.args.get('interval', '1h')
        
        if not symbol:
            return redirect(url_for('index'))
            
        df = get_crypto_data(symbol, interval)
        df = calculate_indicators(df)
        liquidity_zones = identify_liquidity_zones(df)
        fib_levels = calculate_fibonacci_levels(df)
        signals = generate_signals(df, fib_levels, liquidity_zones)

        # Convert DataFrame to JSON for the chart
        chart_data = df.reset_index().to_json(orient='records')

        return render_template('single_analysis.html',
                               symbol=symbol,
                               signals=signals,
                               fib_levels=fib_levels,
                               current_price=df['close'].iloc[-1],
                               chart_data=chart_data,
                               interval=interval)
    
    # Handle POST request from form submission
    analysis_type = request.form.get('analysis_type')

    if analysis_type == 'single':
        symbol = request.form.get('symbol').upper()
        interval = request.form.get('interval')

        df = get_crypto_data(symbol, interval)
        df = calculate_indicators(df)
        liquidity_zones = identify_liquidity_zones(df)
        fib_levels = calculate_fibonacci_levels(df)
        signals = generate_signals(df, fib_levels, liquidity_zones)

        # Convert DataFrame to JSON for the chart
        chart_data = df.reset_index().to_json(orient='records')

        return render_template('single_analysis.html',
                               symbol=symbol,
                               signals=signals,
                               fib_levels=fib_levels,
                               current_price=df['close'].iloc[-1],
                               chart_data=chart_data,
                               interval=interval)

    elif analysis_type == 'multi':
        coins = [
            coin.strip().upper()
            for coin in request.form.get('coins').split(',')
        ]
        interval = request.form.get('interval')

        results = {}
        for coin in coins:
            try:
                df = get_crypto_data(coin, interval)
                df = calculate_indicators(df)
                liquidity_zones = identify_liquidity_zones(df)
                fib_levels = calculate_fibonacci_levels(df)
                signals = generate_signals(df, fib_levels, liquidity_zones)

                if signals['signal'] != "HOLD" and signals['probability'] >= 75:
                    results[coin] = {
                        'signal': signals['signal'],
                        'probability': signals['probability'],
                        'price': df['close'].iloc[-1],
                        'tp': signals['tp'],
                        'sl': signals['sl'],
                        'safety': signals['entry_safety'],
                        'chart_data':
                        df.reset_index().to_json(orient='records')
                    }
            except Exception as e:
                print(f"Error analyzing {coin}: {str(e)}")

        return render_template('multi_analysis.html',
                               results=results,
                               interval=interval)


@app.route('/get_data', methods=['POST'])
@login_required
def get_data():
    symbol = request.json.get('symbol')
    interval = request.json.get('interval')

    df = get_crypto_data(symbol, interval)
    df = calculate_indicators(df)

    return jsonify({
        'data':
        df.reset_index().to_dict(orient='records'),
        'liquidity_zones':
        identify_liquidity_zones(df),
        'fib_levels':
        calculate_fibonacci_levels(df),
        'signals':
        generate_signals(df, calculate_fibonacci_levels(df),
                         identify_liquidity_zones(df))
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=81, debug=True)
