import streamlit as st
import pandas as pd
import joblib

# -----------------------
# Load trained model + scaler + columns
# -----------------------
xgb = joblib.load("xgb_model.pkl")
scaler = joblib.load("scaler.pkl")
columns = joblib.load("columns.pkl")

# -----------------------
# Streamlit UI
# -----------------------
st.title("SDN Traffic Classifier")
st.write("Predict whether network traffic is **Benign** or **Malicious**")

# Create input fields dynamically for each feature
inputs = {}
for col in columns:
    inputs[col] = st.number_input(f"Enter {col}", value=0.0)

# When button is clicked
if st.button("Predict"):
    # Convert to DataFrame with correct columns
    input_df = pd.DataFrame([inputs], columns=columns)

    # Scale the input
    scaled = scaler.transform(input_df)

    # Prediction
    prediction = xgb.predict(scaled)[0]
    result = "Benign" if prediction == 0 else "Malicious"

    st.success(f"Predicted Result: **{result}**")
