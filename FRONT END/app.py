from flask import Flask, render_template, redirect, request, session
import mysql.connector
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import shap

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = 'sensor'

# ---------------------------------------
# Database Connection
# ---------------------------------------
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    port="3306",
    database="sensor"
)

mycursor = mydb.cursor()

def executionquery(query, values):
    mycursor.execute(query, values)
    mydb.commit()

def retrivequery1(query, values):
    mycursor.execute(query, values)
    return mycursor.fetchall()

def retrivequery2(query):
    mycursor.execute(query)
    return mycursor.fetchall()



# ---------------------------------------
# Routes
# ---------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        c_password = request.form['c_password']

        if password == c_password:
            query = "SELECT email FROM users"
            email_data = retrivequery2(query)
            email_data_list = []
            for i in email_data:
                email_data_list.append(i[0])

            if email not in email_data_list:
                query = "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)"
                values = (name, email, password)
                executionquery(query, values)

                return render_template('login.html', message="Successfully Registered!")
            return render_template('register.html', message="This email ID is already exists!")
        return render_template('register.html', message="Conform password is not match!")
    return render_template('register.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        query = "SELECT email FROM users"
        email_data = retrivequery2(query)
        email_data_list = []
        for i in email_data:
            email_data_list.append(i[0])

        if email in email_data_list:
            query = "SELECT * FROM users WHERE email = %s"
            values = (email,)
            password__data = retrivequery1(query, values)
            if password == password__data[0][3]:
                session["user_email"] = email
                session["user_id"] = password__data[0][0]
                session["user_name"] = password__data[0][1]

                return redirect("/home")
            return render_template('login.html', message= "Invalid Password!!")
        return render_template('login.html', message= "This email ID does not exist!")
    return render_template('login.html')





@app.route('/home') 
def home(): 
    return render_template('home.html')



# ---------------------------------------
# Load Random Forest Model
# ---------------------------------------
model = joblib.load("models/rf_model.joblib")

# # -----------------------------
# # Attack Mapping
# # -----------------------------
# attack_mapping = {
#     0: "Blackhole",
#     1: "Flooding",
#     2: "Grayhole",
#     3: "Normal",
#     4: "TDMA"
# }

# # -----------------------------
# # Suggestion Mapping
# # -----------------------------
# suggestion_mapping = {
#     "Blackhole": "Isolate the malicious node immediately and enable secure routing with trust verification.",
#     "Flooding": "Apply rate limiting and packet filtering to block excessive traffic.",
#     "Grayhole": "Monitor selective packet drops and implement acknowledgement-based routing.",
#     "Normal": "Network is safe. Continue regular monitoring.",
#     "TDMA": "Secure time synchronization and validate node authentication."
# }

# # -----------------------------
# # Feature Columns (Must Match Training)
# # -----------------------------
# columns = [
#     'Time','Is_CH','who_CH','Dist_To_CH','ADV_S','ADV_R','JOIN_S',
#     'JOIN_R','SCH_S','SCH_R','Rank','DATA_S','DATA_R',
#     'Data_Sent_To_BS','dist_CH_To_BS','send_code','Expanded_Energy'
# ]

# # -----------------------------
# # Prediction Function
# # -----------------------------
# def prediction_func(input_values):
#     input_df = pd.DataFrame([input_values], columns=columns)

#     # Predict attack type
#     prediction = model.predict(input_df)
#     predicted_class = int(prediction[0])
#     predicted_attack = attack_mapping[predicted_class]

#     # Get suggestion
#     suggestion = suggestion_mapping[predicted_attack]

#     # SHAP explanation for Random Forest
#     explainer = shap.TreeExplainer(model)
#     shap_values = explainer.shap_values(input_df)

#     shap.summary_plot(shap_values, input_df, feature_names=columns, show=False)
#     plt.savefig("static/shap_summary_plot.png", bbox_inches="tight")
#     plt.close()

#     return predicted_attack, suggestion



import os
# ────────────────────────────────────────────────
#  Configuration
# ────────────────────────────────────────────────
MODEL_PATH = "models/rf_model.joblib"
STATIC_FOLDER = "static"
SHAP_FILENAME = "shap_summary_plot.png"
SHAP_PATH = os.path.join(STATIC_FOLDER, SHAP_FILENAME)

# Load model once at startup
try:
    model = joblib.load(MODEL_PATH)
    print("Model loaded successfully")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None
# ────────────────────────────────────────────────
# Mappings
# ────────────────────────────────────────────────
attack_mapping = {
    0: "Blackhole",
    1: "Flooding",
    2: "Grayhole",
    3: "Normal",
    4: "TDMA"
}

suggestion_mapping = {
    "Blackhole": "Isolate the malicious node immediately and enable secure routing with trust verification.",
    "Flooding": "Apply rate limiting and packet filtering to block excessive traffic from suspicious nodes.",
    "Grayhole": "Monitor selective packet dropping behavior and implement acknowledgement-based secure routing.",
    "Normal": "Network behavior is safe. Continue regular monitoring and keep security patches up to date.",
    "TDMA": "Secure time slot synchronization and strengthen node authentication to prevent schedule attacks."
}

FEATURE_COLUMNS = [
    'Time', 'Is_CH', 'who_CH', 'Dist_To_CH', 'ADV_S', 'ADV_R', 'JOIN_S',
    'JOIN_R', 'SCH_S', 'SCH_R', 'Rank', 'DATA_S', 'DATA_R',
    'Data_Sent_To_BS', 'dist_CH_To_BS', 'send_code', 'Expanded_Energy'
]

# ────────────────────────────────────────────────
# Prediction logic
# ────────────────────────────────────────────────
# def make_prediction(input_values):
#     if model is None:
#         return None, None, None

#     try:
#         df = pd.DataFrame([input_values], columns=FEATURE_COLUMNS)

#         # Predict
#         pred = model.predict(df)
#         class_idx = int(pred[0])
#         attack_type = attack_mapping.get(class_idx, "Unknown")

#         suggestion = suggestion_mapping.get(attack_type, "No suggestion available.")

#         # ── SHAP explanation ───────────────────────────────
#         explainer = shap.TreeExplainer(model)
#         shap_values = explainer.shap_values(df)

#         plt.figure(figsize=(10, 7))
#         shap.summary_plot(shap_values, df, feature_names=FEATURE_COLUMNS,
#                           show=False, plot_type="bar")   # or remove plot_type for beeswarm
#         plt.tight_layout()
#         plt.savefig(SHAP_PATH, dpi=120, bbox_inches="tight")
#         plt.close()

#         return attack_type, suggestion, SHAP_FILENAME

#     except Exception as e:
#         print(f"Prediction error: {e}")
#         return None, None, None

import time

def make_prediction(input_values):
    if model is None:
        return None, None, None

    try:
        df = pd.DataFrame([input_values], columns=FEATURE_COLUMNS)

        pred = model.predict(df)
        class_idx = int(pred[0])
        attack_type = attack_mapping.get(class_idx, "Unknown")
        suggestion = suggestion_mapping.get(attack_type, "No suggestion available.")

        # ── SHAP ───────────────────────────────────────────────
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(df)

        # Create unique filename
        timestamp = int(time.time() * 1000)           # milliseconds
        shap_filename = f"shap_plot_{timestamp}.png"
        shap_fullpath = os.path.join(STATIC_FOLDER, shap_filename)

        plt.figure(figsize=(10, 7))
        shap.summary_plot(shap_values, df,
                          feature_names=FEATURE_COLUMNS,
                          plot_type="bar",          # or remove for beeswarm
                          show=False)
        plt.tight_layout()
        plt.savefig(shap_fullpath, dpi=120, bbox_inches="tight")
        plt.close()

        # Return filename + cache buster
        return attack_type, suggestion, f"{shap_filename}?v={timestamp}"

    except Exception as e:
        print(f"Prediction / SHAP error: {e}")
        return None, None, None
    



# -----------------------------
# Prediction Route
# -----------------------------
@app.route('/prediction', methods=['GET', 'POST'])
def prediction():
    result = None
    suggestion = None
    shap_image = None

    if request.method == 'POST':
        try:
            values = [
                float(request.form['Time']),
                float(request.form['Is_CH']),
                float(request.form['who_CH']),
                float(request.form['Dist_To_CH']),
                float(request.form['ADV_S']),
                float(request.form['ADV_R']),
                float(request.form['JOIN_S']),
                float(request.form['JOIN_R']),
                float(request.form['SCH_S']),
                float(request.form['SCH_R']),
                float(request.form['Rank']),
                float(request.form['DATA_S']),
                float(request.form['DATA_R']),
                float(request.form['Data_Sent_To_BS']),
                float(request.form['dist_CH_To_BS']),
                float(request.form['send_code']),
                float(request.form['Expanded_Energy']),
            ]

            result, suggestion, shap_image = make_prediction(values)

        except (KeyError, ValueError) as e:
            return f"Invalid or missing input: {str(e)}", 400

    return render_template(
        'prediction.html',
        result=result,
        suggestion=suggestion,
        shap_image=shap_image
    )
# ---------------------------------------
# Run App
# ---------------------------------------
if __name__ == '__main__':
    app.run(debug=True)