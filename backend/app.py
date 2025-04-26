import os
import time
import mysql.connector
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from deepface import DeepFace
import cv2
from twilio.rest import Client
from datetime import datetime
import logging

# Set up logging to output debug messages to the console
logging.basicConfig(level=logging.DEBUG)

# ---------------------------
# Environment & App Setup
# ---------------------------
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

app = Flask(__name__)
app.secret_key = "secret_key"  # Replace with a strong secret key
CORS(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# Dummy user database for login
users = {"admin": bcrypt.generate_password_hash("password").decode("utf-8")}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

# ---------------------------
# MySQL & Logging Configuration
# ---------------------------
db_config = {
    'user': 'root',
    'password': 'Kjwbo@3116',
    'host': 'localhost',
    'database': 'face_detection_db'
}

def log_event(event_type, message, classification=None, identity=None):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        query = "INSERT INTO detections (event_type, message, identity, classification) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (event_type, message, identity, classification))
        conn.commit()
        logging.debug(f"Logged event with id: {cursor.lastrowid}")
        cursor.close()
        conn.close()
    except Exception as e:
        logging.error(f"Database logging error: {e}")

# ---------------------------
# Twilio SMS Configuration
# ---------------------------
TWILIO_ACCOUNT_SID = 'ACf4228a42ee0b722c84a9264a6118cd97'  # Replace with your Twilio Account SID
TWILIO_AUTH_TOKEN = 'c5269b3fd2270b2d57e4af8ed9ecd230'    # Replace with your Twilio Auth Token
TWILIO_FROM_NUMBER = '+18787866372'         # Replace with your Twilio phone number
ALERT_TO_NUMBER = '+918850208224'            # Replace with your alert recipient phone number
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def send_sms_alert(message):
    try:
        twilio_client.messages.create(
            body=message,
            from_=TWILIO_FROM_NUMBER,
            to=ALERT_TO_NUMBER
        )
    except Exception as e:
        logging.error(f"SMS sending error: {e}")

# ---------------------------
# Alert Rate Limiting
# ---------------------------
last_alert_time = {"SAFE": 0, "INTRUDER_DETECTED": 0}
ALERT_INTERVAL = 60  # seconds between alerts

# ---------------------------
# Directory Configuration
# ---------------------------
BASE_DIR = os.path.dirname(__file__)
KNOWN_FACES = os.path.join(BASE_DIR, "known_faces")
UNKNOWN_FACES = os.path.join(BASE_DIR, "unknown_faces")
os.makedirs(KNOWN_FACES, exist_ok=True)
os.makedirs(UNKNOWN_FACES, exist_ok=True)

# ---------------------------
# Routes for Authentication
# ---------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username in users and bcrypt.check_password_hash(users[username], password):
            user = User(username)
            login_user(user)
            return redirect(url_for("home"))
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ---------------------------
# Home (Dashboard) Route
# ---------------------------
@app.route("/")
@login_required
def home():
    return render_template("index.html")

# ---------------------------
# Face Detection & Recognition Endpoint
# ---------------------------
@app.route("/check-intruder", methods=["POST"])
@login_required
def check_intruder():
    try:
        if "image" not in request.files:
            return jsonify({"result": "ERROR", "message": "No image uploaded"})
        image = request.files["image"]
        if image.filename == "":
            return jsonify({"result": "ERROR", "message": "Empty filename"})

        # Save the uploaded image temporarily
        image_path = os.path.join(UNKNOWN_FACES, "temp.jpg")
        image.save(image_path)
        logging.debug(f"Image saved to {image_path}")

        # Attempt to read the image using OpenCV
        try:
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Failed to load image (possibly corrupted or premature end of JPEG file).")
        except Exception as e:
            logging.error(f"Image processing error: {e}")
            return jsonify({"result": "ERROR", "message": f"Image processing error: {str(e)}"})

        # Use DeepFace to perform recognition using FaceNet and MTCNN for detection
        try:
            results = DeepFace.find(
                img_path=image_path,
                db_path=KNOWN_FACES,
                model_name="Facenet",
                detector_backend="mtcnn",
                distance_metric="cosine",
                enforce_detection=True,
                silent=True
            )
        except Exception as e:
            if "Face could not be detected" in str(e):
                log_event("NO_FACE_DETECTED", "No face found in the image")
                return jsonify({"result": "NO_FACE_DETECTED", "message": "No face detected"})
            else:
                logging.error(f"Detection error: {e}")
                return jsonify({"result": "ERROR", "message": f"Detection error: {str(e)}"})

        current_time = time.time()
        if len(results[0]) == 0:
            if current_time - last_alert_time["INTRUDER_DETECTED"] > ALERT_INTERVAL:
                send_sms_alert("Alert: Intruder detected!")
                last_alert_time["INTRUDER_DETECTED"] = current_time
            log_event("INTRUDER_DETECTED", "Unknown individual detected", classification="AI_unknown")
            return jsonify({"result": "INTRUDER_DETECTED", "message": "Unknown individual detected"})
        else:
            identity = results[0]["identity"].iloc[0]
            if current_time - last_alert_time["SAFE"] > ALERT_INTERVAL:
                send_sms_alert(f"Access granted for {identity}.")
                last_alert_time["SAFE"] = current_time
            log_event("SAFE", "Authorized personnel recognized", classification="AI_recognized", identity=identity)
            return jsonify({"result": "SAFE", "message": "Authorized personnel recognized", "identity": identity})
    except Exception as e:
        logging.exception("Exception in /check-intruder endpoint")
        return jsonify({"result": "ERROR", "message": f"Server error: {str(e)}"})

# ---------------------------
# Manual Classification Endpoint
# ---------------------------
@app.route("/manual-classification", methods=["POST"])
@login_required
def manual_classification():
    try:
        classification = request.form.get("classification")
        if "image" not in request.files:
            return jsonify({"result": "ERROR", "message": "No image uploaded for classification"})
        image = request.files["image"]

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if classification == "manual_known":
            filename = f"manual_{timestamp}.jpg"
            save_path = os.path.join(KNOWN_FACES, filename)
            image.save(save_path)
            log_event("MANUAL_KNOWN", "User declared known person", classification="manual_known", identity=filename)
            return jsonify({"result": "MANUAL_KNOWN", "message": f"Manually added as known person: {filename}"})
        elif classification == "intruder":
            log_event("MANUAL_INTRUDER", "User declared intruder", classification="manual_intruder")
            return jsonify({"result": "MANUAL_INTRUDER", "message": "Manually declared as intruder"})
        elif classification == "safe":
            log_event("MANUAL_SAFE", "User accepted AI recognition", classification="manual_safe")
            return jsonify({"result": "MANUAL_SAFE", "message": "Face accepted as known (AI recognized)"})
        else:
            return jsonify({"result": "ERROR", "message": "Invalid classification"})
    except Exception as e:
        logging.exception("Exception in /manual-classification endpoint")
        return jsonify({"result": "ERROR", "message": f"Server error: {str(e)}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

