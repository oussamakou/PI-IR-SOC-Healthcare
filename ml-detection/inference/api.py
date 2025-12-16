"""
ML Detection API - Real-time anomaly detection for healthcare security alerts
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import joblib
import numpy as np
from typing import Optional
import logging
from prometheus_client import Counter, Histogram, generate_latest
from prometheus_client import CONTENT_TYPE_LATEST
from fastapi.responses import Response
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Prometheus metrics
PREDICTIONS_TOTAL = Counter('ml_predictions_total', 'Total predictions made')
ANOMALIES_DETECTED = Counter('ml_anomalies_detected', 'Total anomalies detected')
PREDICTION_LATENCY = Histogram('ml_prediction_latency_seconds', 'Prediction latency')

app = FastAPI(
    title="Healthcare ML Detection API",
    description="Real-time anomaly detection for healthcare security workloads",
    version="1.0.0"
)

# Global model cache
model_cache = {}

class Alert(BaseModel):
    """Alert data model for ML inference"""
    source_ip: str = Field(..., description="Source IP address")
    dest_ip: str = Field(..., description="Destination IP address")
    port: int = Field(..., ge=0, le=65535, description="Destination port")
    protocol: str = Field(default="tcp", description="Network protocol")
    bytes_sent: int = Field(default=0, ge=0, description="Bytes sent")
    bytes_received: int = Field(default=0, ge=0, description="Bytes received")

class PredictionResponse(BaseModel):
    """ML prediction response"""
    is_anomaly: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    model_version: str
    alert: Alert

def load_model(model_path: str = "/models/network_anomaly.pkl"):
    """Load ML model from disk with caching"""
    if model_path in model_cache:
        return model_cache[model_path]
    
    try:
        if not os.path.exists(model_path):
            logger.warning(f"Model not found at {model_path}, using dummy model")
            # Return a dummy model for development
            from sklearn.ensemble import IsolationForest
            model = IsolationForest(contamination=0.1, random_state=42)
            # Train on dummy data
            X_dummy = np.random.randn(100, 3)
            model.fit(X_dummy)
            model_cache[model_path] = model
            return model
        
        model = joblib.load(model_path)
        model_cache[model_path] = model
        logger.info(f"Loaded model from {model_path}")
        return model
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        raise HTTPException(status_code=503, detail="Model not available")

def extract_features(alert: Alert) -> np.ndarray:
    """Extract numerical features from alert for ML model"""
    # Feature engineering
    features = [
        alert.port,
        alert.bytes_sent,
        alert.bytes_received
    ]
    return np.array([features])

@app.post("/predict", response_model=PredictionResponse)
async def predict_anomaly(alert: Alert):
    """
    Predict if an alert represents an anomaly
    
    Returns:
        - is_anomaly: Boolean indicating if alert is anomalous
        - confidence: Confidence score (0.0 to 1.0)
        - model_version: Version of the ML model used
    """
    with PREDICTION_LATENCY.time():
        try:
            # Load model
            model = load_model()
            
            # Extract features
            features = extract_features(alert)
            
            # Make prediction
            prediction = model.predict(features)[0]
            
            # Get anomaly score (distance from normal)
            # For IsolationForest: -1 = anomaly, 1 = normal
            is_anomaly = prediction == -1
            
            # Calculate confidence score
            # decision_function returns anomaly score (lower = more anomalous)
            anomaly_score = model.decision_function(features)[0]
            # Normalize to 0-1 range (higher = more confident it's an anomaly)
            confidence = 1.0 / (1.0 + np.exp(anomaly_score))
            
            # Update metrics
            PREDICTIONS_TOTAL.inc()
            if is_anomaly:
                ANOMALIES_DETECTED.inc()
            
            logger.info(f"Prediction: is_anomaly={is_anomaly}, confidence={confidence:.3f}")
            
            return PredictionResponse(
                is_anomaly=is_anomaly,
                confidence=float(confidence),
                model_version="v1.0.0",
                alert=alert
            )
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Verify model can be loaded
        load_model()
        return {
            "status": "healthy",
            "model_loaded": True,
            "version": "1.0.0"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "model_loaded": False,
            "error": str(e)
        }

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "name": "Healthcare ML Detection API",
        "version": "1.0.0",
        "endpoints": {
            "predict": "/predict",
            "health": "/health",
            "metrics": "/metrics",
            "docs": "/docs"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
