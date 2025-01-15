import time
import hashlib
from collections import defaultdict
from flask import Flask, request, jsonify
import random
import string
from datetime import datetime

# Flask application setup
app = Flask(__name__)

# Configuration
MAX_REQUESTS_PER_MINUTE = 60
BLACKLIST_THRESHOLD = 100
CAPTCHA_THRESHOLD = 5
REQUEST_WINDOW = 60  # seconds

# In-memory storage for rate limiting, blacklisting, and CAPTCHA verification
rate_limits = defaultdict(list)
blacklisted_ips = set()
captcha_verified = defaultdict(bool)

# Logging function
def log_attack(ip, reason):
    print(f"[{datetime.now()}] [ALERT] {reason} from IP: {ip}")

# Rate limiting handler
def is_rate_limited(ip):
    current_time = time.time()
    # Clean up requests that are outside the rate limit window
    rate_limits[ip] = [timestamp for timestamp in rate_limits[ip] if current_time - timestamp < REQUEST_WINDOW]
    
    # Check if the number of requests exceeds the limit
    if len(rate_limits[ip]) >= MAX_REQUESTS_PER_MINUTE:
        log_attack(ip, "Rate limit exceeded")
        return True
    rate_limits[ip].append(current_time)
    return False

# Blacklist check
def is_blacklisted(ip):
    if ip in blacklisted_ips:
        log_attack(ip, "IP is blacklisted")
        return True
    return False

# Function to simulate CAPTCHA generation
def generate_captcha():
    captcha_text = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    captcha_hash = hashlib.sha256(captcha_text.encode('utf-8')).hexdigest()  # Store the hashed value of the captcha
    return captcha_text, captcha_hash

# CAPTCHA verification handler
def verify_captcha(ip, user_captcha_input):
    # Simulate CAPTCHA challenge for certain IPs based on traffic patterns
    if captcha_verified[ip]:
        return True

    captcha_text, captcha_hash = generate_captcha()
    print(f"[INFO] CAPTCHA challenge generated: {captcha_text}")
    
    # Simulating that the user must provide the correct CAPTCHA input
    if user_captcha_input == captcha_text:
        captcha_verified[ip] = True
        return True
    else:
        log_attack(ip, "Incorrect CAPTCHA response")
        return False

# Route that handles user requests and applies security measures
@app.route("/", methods=["GET", "POST"])
def index():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')

    # Step 1: Check if the IP is blacklisted
    if is_blacklisted(ip):
        return jsonify({"error": "Access denied"}), 403

    # Step 2: Rate limiting check
    if is_rate_limited(ip):
        return jsonify({"error": "Too many requests, please try again later"}), 429

    # Step 3: CAPTCHA challenge for suspected bot behavior
    # This could be extended to check for high request rates or specific patterns
    if len(rate_limits[ip]) > CAPTCHA_THRESHOLD and not captcha_verified[ip]:
        user_captcha_input = request.args.get('captcha')  # Get CAPTCHA response from query parameter
        if not verify_captcha(ip, user_captcha_input):
            return jsonify({"error": "Invalid CAPTCHA, please verify yourself."}), 400

    # Normal request handling (Here, we just return a simple message)
    return jsonify({"message": "Request processed successfully."})

# Function to blacklist an IP address
def blacklist_ip(ip):
    blacklisted_ips.add(ip)
    print(f"[INFO] IP {ip} added to blacklist.")

# Monitor traffic patterns and detect potential DDoS attempts
def detect_ddos():
    # Example method to detect anomalous traffic patterns (e.g., traffic spikes)
    current_time = time.time()
    ip_count = defaultdict(int)
    
    for ip, timestamps in rate_limits.items():
        ip_count[ip] = len([timestamp for timestamp in timestamps if current_time - timestamp < REQUEST_WINDOW])
    
    # Simple heuristic: Any IP that sends more than 10 requests in 10 seconds
    for ip, count in ip_count.items():
        if count > 10:
            log_attack(ip, "Possible DDoS attack detected (high request rate)")
            blacklist_ip(ip)

# Background task to monitor traffic and detect DDoS
def monitor_traffic():
    while True:
        time.sleep(5)  # Monitor every 5 seconds
        detect_ddos()

# This should be run in a separate thread or process to continually monitor traffic
from threading import Thread
traffic_monitor_thread = Thread(target=monitor_traffic, daemon=True)
traffic_monitor_thread.start()

# Run the Flask app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
