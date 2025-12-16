"""
Wazuh Connector - Pulls alerts from team's Wazuh Manager and enriches with ML scoring
"""
import requests
import time
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment variables
WAZUH_API_URL = os.getenv('WAZUH_API_URL', 'https://localhost:55000')
WAZUH_USER = os.getenv('WAZUH_USER', 'admin')
WAZUH_PASS = os.getenv('WAZUH_PASS', 'admin')
ML_API_URL = os.getenv('ML_API_URL', 'http://ml-inference:8000')
SHUFFLE_WEBHOOK_URL = os.getenv('SHUFFLE_WEBHOOK_URL')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '30'))  # seconds

class WazuhConnector:
    """Connector to pull alerts from Wazuh and enrich with ML"""
    
    def __init__(self):
        self.api_url = WAZUH_API_URL
        self.username = WAZUH_USER
        self.password = WAZUH_PASS
        self.ml_api_url = ML_API_URL
        self.shuffle_webhook = SHUFFLE_WEBHOOK_URL
        self.token = None
        self.session = requests.Session()
        self.session.verify = False  # For self-signed certs
        
    def authenticate(self) -> bool:
        """Authenticate with Wazuh API and get JWT token"""
        try:
            response = self.session.post(
                f"{self.api_url}/security/user/authenticate",
                auth=(self.username, self.password),
                timeout=10
            )
            response.raise_for_status()
            self.token = response.json()['data']['token']
            logger.info("Successfully authenticated with Wazuh API")
            return True
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False
    
    def fetch_alerts(self, last_timestamp: str) -> List[Dict]:
        """Fetch new alerts from Wazuh since last timestamp"""
        if not self.token:
            if not self.authenticate():
                return []
        
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            params = {
                'timestamp': last_timestamp,
                'limit': 100,
                'sort': '+timestamp'
            }
            
            response = self.session.get(
                f"{self.api_url}/alerts",
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 401:
                # Token expired, re-authenticate
                logger.warning("Token expired, re-authenticating...")
                if self.authenticate():
                    return self.fetch_alerts(last_timestamp)
                return []
            
            response.raise_for_status()
            alerts = response.json()['data']['affected_items']
            logger.info(f"Fetched {len(alerts)} new alerts from Wazuh")
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {e}")
            return []
    
    def enrich_with_ml(self, alert: Dict) -> Optional[Dict]:
        """Send alert to ML API for anomaly scoring"""
        try:
            # Extract relevant fields for ML model
            data = alert.get('data', {})
            ml_payload = {
                'source_ip': data.get('srcip', '0.0.0.0'),
                'dest_ip': data.get('dstip', '0.0.0.0'),
                'port': int(data.get('dstport', 0)),
                'protocol': data.get('protocol', 'unknown'),
                'bytes_sent': int(data.get('bytes_sent', 0)),
                'bytes_received': int(data.get('bytes_received', 0))
            }
            
            response = requests.post(
                f"{self.ml_api_url}/predict",
                json=ml_payload,
                timeout=5
            )
            response.raise_for_status()
            ml_result = response.json()
            
            logger.debug(f"ML enrichment: is_anomaly={ml_result.get('is_anomaly')}, "
                        f"confidence={ml_result.get('confidence')}")
            
            return ml_result
            
        except Exception as e:
            logger.warning(f"ML enrichment failed: {e}")
            return None
    
    def send_to_shuffle(self, enriched_alert: Dict) -> bool:
        """Forward high-confidence alerts to Shuffle SOAR"""
        if not self.shuffle_webhook:
            logger.warning("Shuffle webhook URL not configured")
            return False
        
        try:
            # Only send if ML confidence is high
            ml_score = enriched_alert.get('ml_enrichment', {})
            confidence = ml_score.get('confidence', 0)
            
            if confidence < 0.7:
                logger.debug(f"Alert confidence {confidence} below threshold, skipping Shuffle")
                return False
            
            response = requests.post(
                self.shuffle_webhook,
                json=enriched_alert,
                timeout=10
            )
            response.raise_for_status()
            logger.info(f"Sent high-confidence alert to Shuffle (confidence={confidence})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send to Shuffle: {e}")
            return False
    
    def process_alert(self, alert: Dict) -> None:
        """Process a single alert: enrich with ML and forward to Shuffle"""
        alert_id = alert.get('id', 'unknown')
        rule_description = alert.get('rule', {}).get('description', 'No description')
        
        logger.info(f"Processing alert {alert_id}: {rule_description}")
        
        # Enrich with ML
        ml_result = self.enrich_with_ml(alert)
        
        # Create enriched alert
        enriched_alert = {
            **alert,
            'ml_enrichment': ml_result,
            'processed_at': datetime.utcnow().isoformat(),
            'pipeline_version': 'v1.0.0'
        }
        
        # Send to Shuffle if high confidence
        self.send_to_shuffle(enriched_alert)
    
    def run(self) -> None:
        """Main loop: continuously poll Wazuh and process alerts"""
        logger.info("Starting Wazuh Connector...")
        logger.info(f"Wazuh API: {self.api_url}")
        logger.info(f"ML API: {self.ml_api_url}")
        logger.info(f"Poll interval: {POLL_INTERVAL}s")
        
        # Authenticate on startup
        if not self.authenticate():
            logger.error("Initial authentication failed, exiting")
            return
        
        last_timestamp = datetime.utcnow().isoformat()
        
        while True:
            try:
                # Fetch new alerts
                alerts = self.fetch_alerts(last_timestamp)
                
                # Process each alert
                for alert in alerts:
                    self.process_alert(alert)
                
                # Update last timestamp
                if alerts:
                    last_timestamp = alerts[-1].get('timestamp', last_timestamp)
                
                # Sleep before next poll
                time.sleep(POLL_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("Shutting down gracefully...")
                break
            except Exception as e:
                logger.error(f"Unexpected error in main loop: {e}")
                time.sleep(60)  # Wait before retrying

if __name__ == '__main__':
    connector = WazuhConnector()
    connector.run()
