# Development Environment Configuration
environment = "dev"

# Update these with your team's actual endpoints
wazuh_api_url      = "https://aziz-wazuh.tailscale:55000"
wazuh_api_user     = "admin"
wazuh_api_password = "CHANGE_ME"  # Get from Aziz

shuffle_webhook_url = "http://localhost:3001/api/v1/hooks/webhook_detection_pipeline"

# Optional: MISP integration (get from Amine)
misp_api_url = ""
misp_api_key = ""

# ML Configuration
ml_model_version      = "v1.0.0"
ml_inference_replicas = 1
