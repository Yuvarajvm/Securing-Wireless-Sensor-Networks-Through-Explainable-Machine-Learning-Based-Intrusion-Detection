# Securing Wireless Sensor Networks Through Explainable Machine Learning-Based Intrusion Detection

A Flask-based web application for detecting intrusions in Wireless Sensor Networks (WSNs) using Machine Learning and Explainable AI (XAI). The system predicts network attacks such as Blackhole, Flooding, Grayhole, and TDMA attacks using a trained Random Forest model and explains predictions using SHAP visualization.

---

## 📌 Project Overview

Wireless Sensor Networks are vulnerable to various cyberattacks due to their distributed and resource-constrained nature. This project provides a Machine Learning-powered Intrusion Detection System (IDS) that identifies malicious activities and improves network security.

The application uses:
- Random Forest Machine Learning Model
- SHAP Explainable AI
- Flask Web Framework
- MySQL Database Integration

The system not only predicts attacks but also provides security suggestions and feature importance explanations using SHAP plots.

---

## 🚀 Features

- 🔐 User Registration & Login Authentication
- 🤖 Intrusion Detection using Random Forest
- 📊 SHAP Explainable AI Visualization
- 📈 Dynamic Attack Prediction System
- 🛡️ Detection of Multiple WSN Attacks
- 💡 Security Recommendations for Each Attack
- 🌐 Flask Web Application Interface
- 🗄️ MySQL Database Integration

---

## 🧠 Detected Attack Types

- Blackhole Attack
- Flooding Attack
- Grayhole Attack
- TDMA Attack
- Normal Network Behavior

---

## 🛠️ Technologies Used

### Backend
- Python
- Flask

### Machine Learning
- Scikit-learn
- Random Forest
- SHAP

### Database
- MySQL

### Libraries
- Pandas
- NumPy
- Matplotlib
- Joblib

---

## 📂 Project Structure

```bash
├── models/
│   └── rf_model.joblib
├── static/
├── templates/
├── app.py
├── requirements.txt
└── README.md
