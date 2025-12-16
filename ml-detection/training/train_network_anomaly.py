"""
Train Network Anomaly Detection Model
Uses Isolation Forest to detect unusual network traffic patterns in healthcare workloads
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_synthetic_data(n_normal=1000, n_anomaly=100):
    """
    Generate synthetic training data for healthcare network traffic
    
    In production, replace this with real Zeek logs from Yessine's Security Onion
    """
    np.random.seed(42)
    
    # Normal traffic patterns for healthcare
    normal_data = pd.DataFrame({
        # Common healthcare ports: HL7 (2575), DICOM (4242, 11112), HTTPS (443)
        'port': np.random.choice([2575, 4242, 11112, 443, 80], n_normal),
        'bytes_sent': np.random.normal(5000, 1000, n_normal),  # Normal HL7/DICOM messages
        'bytes_received': np.random.normal(10000, 2000, n_normal),
        'label': 0  # Normal
    })
    
    # Anomalous traffic patterns
    anomaly_data = pd.DataFrame({
        # Suspicious ports: C2 channels, backdoors
        'port': np.random.choice([4444, 1337, 31337, 8888, 9999], n_anomaly),
        'bytes_sent': np.random.normal(50000, 10000, n_anomaly),  # Data exfiltration
        'bytes_received': np.random.normal(500, 100, n_anomaly),  # Command responses
        'label': 1  # Anomaly
    })
    
    # Combine datasets
    data = pd.concat([normal_data, anomaly_data], ignore_index=True)
    
    # Shuffle
    data = data.sample(frac=1, random_state=42).reset_index(drop=True)
    
    logger.info(f"Generated {len(data)} samples ({n_normal} normal, {n_anomaly} anomalies)")
    
    return data

def train_model(data: pd.DataFrame, contamination=0.1):
    """Train Isolation Forest model"""
    
    # Separate features and labels
    X = data[['port', 'bytes_sent', 'bytes_received']]
    y = data['label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info(f"Training set: {len(X_train)} samples")
    logger.info(f"Test set: {len(X_test)} samples")
    
    # Train Isolation Forest
    logger.info("Training Isolation Forest model...")
    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        max_features=1.0
    )
    
    model.fit(X_train)
    
    # Evaluate on test set
    y_pred = model.predict(X_test)
    # Convert predictions: -1 (anomaly) -> 1, 1 (normal) -> 0
    y_pred_binary = np.where(y_pred == -1, 1, 0)
    
    logger.info("\n=== Model Evaluation ===")
    logger.info("\nClassification Report:")
    print(classification_report(y_test, y_pred_binary, target_names=['Normal', 'Anomaly']))
    
    logger.info("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred_binary))
    
    return model

def save_model(model, output_path='/models/network_anomaly.pkl'):
    """Save trained model to disk"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    joblib.dump(model, output_path)
    logger.info(f"Model saved to {output_path}")

def main():
    """Main training pipeline"""
    logger.info("Starting ML model training pipeline...")
    
    # Generate training data
    # TODO: Replace with real Zeek logs from Security Onion
    data = generate_synthetic_data(n_normal=1000, n_anomaly=100)
    
    # Train model
    model = train_model(data, contamination=0.1)
    
    # Save model
    save_model(model, output_path='../models/network_anomaly.pkl')
    
    logger.info("Training complete!")

if __name__ == '__main__':
    main()
