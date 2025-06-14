# 🔒 Real-Time Intruder Detection System

This is an AI-based real-time intruder detection system using **DeepFace**, **Flask**, and **OpenCV**. It captures live webcam footage, detects and recognizes faces, logs entries into a MySQL database, and sends real-time SMS alerts using Twilio. The project includes an interactive web dashboard with login protection, manual overrides, and animation-enhanced UI.

---

## 📌 Features

- 🧠 **Face Recognition with DeepFace (Facenet)**
- 📷 **Live webcam capture every 3 seconds**
- 🧍‍♂️ **Distinguishes known persons vs intruders**
- 📲 **Real-time SMS alerts via Twilio**
- 📚 **MySQL logging of each detection**
- 🖥️ **Login-secured interactive web dashboard**
- 🔘 **Manual override: allow or mark as intruder**
- 🎨 **Modern UI with animated background & status**

---

## 📁 Project Structure

```
IntruderDetection/
├── app.py                  # Flask backend
├── templates/
│   ├── login.html          # Login page
│   └── index.html          # Main dashboard
├── known_faces/            # Folder for storing known face images
├── unknown_faces/          # Temporary folder for incoming frames
├── requirements.txt        # All Python dependencies
└── README.md               # This file
```

---

## ⚙️ Technologies Used

- **Python 3.11**
- **Flask** (Backend Web Framework)
- **DeepFace** (Face recognition – Facenet model)
- **OpenCV** (Image processing)
- **Twilio API** (SMS alerts)
- **MySQL** (Event logging)
- **HTML/CSS/JavaScript** (Frontend)
- **Flask-Login + Bcrypt** (Authentication & security)

---

## 🚀 How to Run

### 1. Clone the Repository

```bash
git clone git@github.com:JD5505/IntruderDetection.git
cd IntruderDetection
```

### 2. Set Up Virtual Environment (optional but recommended)

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

Create a `.env` file in the root directory with:

```env
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE=your_twilio_number
RECEIVER_PHONE=your_verified_phone_number
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password
MYSQL_DB=face_detection_db
```

Also, create folders:

```bash
mkdir known_faces unknown_faces
```

### 5. Run the App

```bash
python app.py
```

Then open your browser and go to:  
👉 `http://localhost:5000/login`

---

## 🔑 Login Credentials

Default credentials are set in the database. Update `app.py` or insert into MySQL as needed.  
> **Username:** `admin`  
> **Password:** `admin123` (hashed with bcrypt)

---

## 📊 Database

MySQL table `detections` stores:

- ID (auto increment)
- Timestamp
- Identity (filename if known)
- Classification (`SAFE`, `INTRUDER`, `NO_FACE_DETECTED`)
- Message

Make sure the `face_detection_db` database exists.

---

## 📱 Access from Another Device

- Connect both devices to the same network.
- Run Flask with:
  ```bash
  app.run(host='0.0.0.0', port=5000)
  ```
- Access via:  
  `http://<your-laptop-local-IP>:5000`

To allow public access:
```bash
ngrok http 5000
```

---

## ✅ Future Enhancements

- Email/push notifications
- Face re-training from web
- Role-based access system
- Multi-camera support
- Cloud-based storage

---

## 📄 License

This project is for educational use only. External contributions welcome via pull requests.

---

## 🙌 Acknowledgements

- [DeepFace](https://github.com/serengil/deepface)
- [Twilio](https://www.twilio.com/)
- [OpenCV](https://opencv.org/)
- [Flask](https://flask.palletsprojects.com/)