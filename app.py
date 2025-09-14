import streamlit as st
import pandas as pd
import joblib
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import time

# -----------------------
# Page Configuration
# -----------------------
st.set_page_config(
    page_title="SDN Traffic Classifier",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -----------------------
# Custom CSS for styling
# -----------------------
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2rem;
    }
    
    .subtitle {
        font-size: 1.2rem;
        text-align: center;
        color: #666;
        margin-bottom: 3rem;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    
    .benign-result {
        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        font-size: 1.5rem;
        font-weight: bold;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(17, 153, 142, 0.3);
    }
    
    .malicious-result {
        background: linear-gradient(135deg, #fc466b 0%, #3f5efb 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        font-size: 1.5rem;
        font-weight: bold;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(252, 70, 107, 0.3);
    }
    
    .stButton > button {
        width: 100%;
        height: 3rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border: none;
        border-radius: 25px;
        color: white;
        font-size: 1.1rem;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
    }
    
    .sidebar-content {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# -----------------------
# Load trained model + scaler + columns
# -----------------------
@st.cache_resource
def load_models():
    try:
        xgb = joblib.load("xgb_model.pkl")
        scaler = joblib.load("scaler.pkl")
        columns = joblib.load("columns.pkl")
        return xgb, scaler, columns
    except FileNotFoundError as e:
        st.error(f"Model files not found: {e}")
        st.stop()

xgb, scaler, columns = load_models()

# -----------------------
# Initialize session state
# -----------------------
if 'prediction_history' not in st.session_state:
    st.session_state.prediction_history = []

# -----------------------
# Sidebar
# -----------------------
st.sidebar.markdown("""
<div class="sidebar-content">
    <h3>🛡️ SDN Security Monitor</h3>
    <p>Advanced network traffic analysis using machine learning</p>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("### 📊 Model Information")
st.sidebar.info(f"""
**Features:** {len(columns)}  
**Algorithm:** XGBoost  
**Status:** ✅ Ready  
**Last Updated:** {datetime.now().strftime('%Y-%m-%d')}
""")

# Input method selection
input_method = st.sidebar.radio(
    "🔧 Input Method",
    ["Manual Entry", "Batch Upload"]
)

# -----------------------
# Main Application
# -----------------------
st.markdown('<h1 class="main-header">🛡️ SDN Traffic Classifier</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Advanced Machine Learning for Network Security Analysis</p>', unsafe_allow_html=True)

# Create columns for layout
col1, col2 = st.columns([2, 1])

with col1:
    if input_method == "Manual Entry":
        st.markdown("### 📝 Feature Input")
        
        # Group features into categories for better organization
        feature_categories = {
            "Basic Metrics": columns[:len(columns)//3],
            "Advanced Metrics": columns[len(columns)//3:2*len(columns)//3],
            "Statistical Features": columns[2*len(columns)//3:]
        }
        
        inputs = {}
        
        # Create tabs for different feature categories
        tabs = st.tabs(list(feature_categories.keys()))
        
        for i, (category, features) in enumerate(feature_categories.items()):
            with tabs[i]:
                cols = st.columns(2)
                for j, col in enumerate(features):
                    with cols[j % 2]:
                        inputs[col] = st.number_input(
                            f"{col}",
                            value=0.0,
                            key=f"input_{col}",
                            help=f"Enter value for {col}"
                        )
    
    
    elif input_method == "Batch Upload":
        st.markdown("### 📁 Batch Processing")
        
        uploaded_file = st.file_uploader(
            "Upload CSV file with network traffic data",
            type=['csv'],
            help="Upload a CSV file with the same feature columns as the model"
        )
        
        if uploaded_file is not None:
            try:
                batch_df = pd.read_csv(uploaded_file)
                st.success(f"✅ Uploaded {len(batch_df)} records")
                
                if st.button("🔍 Analyze Batch"):
                    # Process batch predictions
                    progress_bar = st.progress(0)
                    results = []
                    
                    for i in range(len(batch_df)):
                        # Ensure columns match
                        input_row = batch_df.iloc[i:i+1].reindex(columns=columns, fill_value=0)
                        scaled = scaler.transform(input_row)
                        prediction = xgb.predict(scaled)[0]
                        probability = xgb.predict_proba(scaled)[0]
                        
                        results.append({
                            'Index': i,
                            'Prediction': 'Benign' if prediction == 0 else 'Malicious',
                            'Confidence': max(probability),
                            'Benign_Prob': probability[0],
                            'Malicious_Prob': probability[1]
                        })
                        
                        progress_bar.progress((i + 1) / len(batch_df))
                    
                    results_df = pd.DataFrame(results)
                    
                    # Display batch results
                    st.markdown("### 📊 Batch Results")
                    
                    col_a, col_b, col_c = st.columns(3)
                    with col_a:
                        benign_count = sum(1 for r in results if r['Prediction'] == 'Benign')
                        st.metric("Benign Traffic", benign_count)
                    
                    with col_b:
                        malicious_count = sum(1 for r in results if r['Prediction'] == 'Malicious')
                        st.metric("Malicious Traffic", malicious_count)
                    
                    with col_c:
                        avg_confidence = np.mean([r['Confidence'] for r in results])
                        st.metric("Avg Confidence", f"{avg_confidence:.2%}")
                    
                    st.dataframe(results_df, use_container_width=True)
                    
            except Exception as e:
                st.error(f"Error processing file: {e}")

with col2:
    st.markdown("### 📈 Prediction Dashboard")
    
    # Prediction button
    if input_method != "Batch Upload":
        predict_button = st.button("🔍 Analyze Traffic", key="predict_btn")
        
        if predict_button:
            try:
                # Convert to DataFrame with correct columns
                input_df = pd.DataFrame([inputs], columns=columns)
                
                # Scale the input
                scaled = scaler.transform(input_df)
                
                # Get prediction and probabilities
                prediction = xgb.predict(scaled)[0]
                probabilities = xgb.predict_proba(scaled)[0]
                
                result = "Benign" if prediction == 0 else "Malicious"
                confidence = max(probabilities)
                
                # Store in history
                st.session_state.prediction_history.append({
                    'timestamp': datetime.now(),
                    'result': result,
                    'confidence': confidence,
                    'benign_prob': probabilities[0],
                    'malicious_prob': probabilities[1]
                })
                
                # Display result with styling
                if result == "Benign":
                    st.markdown(f"""
                    <div class="benign-result">
                        ✅ BENIGN TRAFFIC<br>
                        <small>Confidence: {confidence:.1%}</small>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="malicious-result">
                        ⚠️ MALICIOUS TRAFFIC<br>
                        <small>Confidence: {confidence:.1%}</small>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Probability gauge chart
                fig = go.Figure(go.Indicator(
                    mode="gauge+number+delta",
                    value=probabilities[1] * 100,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "Malicious Probability"},
                    delta={'reference': 50},
                    gauge={
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 25], 'color': "lightgreen"},
                            {'range': [25, 50], 'color': "yellow"},
                            {'range': [50, 75], 'color': "orange"},
                            {'range': [75, 100], 'color': "red"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': 90
                        }
                    }
                ))
                
                fig.update_layout(height=300, margin=dict(l=20, r=20, t=40, b=20))
                st.plotly_chart(fig, use_container_width=True)
                
            except Exception as e:
                st.error(f"Prediction error: {e}")
    
    # Prediction history
    if st.session_state.prediction_history:
        st.markdown("### 📊 Recent Predictions")
        
        history_df = pd.DataFrame(st.session_state.prediction_history[-10:])  # Last 10
        
        # Create a timeline chart
        fig = px.scatter(
            history_df, 
            x='timestamp', 
            y='confidence',
            color='result',
            color_discrete_map={'Benign': 'green', 'Malicious': 'red'},
            title="Prediction Timeline"
        )
        fig.update_layout(height=300, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig, use_container_width=True)
        
        # Summary metrics
        col_x, col_y = st.columns(2)
        with col_x:
            total_predictions = len(st.session_state.prediction_history)
            st.metric("Total Predictions", total_predictions)
        
        with col_y:
            if st.button("🗑️ Clear History"):
                st.session_state.prediction_history = []
                st.rerun()

# -----------------------
# Footer
# -----------------------
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 2rem 0;">
    <p>🛡️ SDN Traffic Classifier v2.0 | Powered by XGBoost & Streamlit</p>
    <p><small>Protecting your network with advanced machine learning</small></p>
</div>
""", unsafe_allow_html=True)

