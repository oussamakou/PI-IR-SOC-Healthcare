variable "environment" {
  description = "Environment name (dev, prod)"
  type        = string
  default     = "dev"
}

variable "kubeconfig_path" {
  description = "Path to kubeconfig file"
  type        = string
  default     = "~/.kube/config"
}

# Wazuh Integration
variable "wazuh_api_url" {
  description = "Wazuh Manager API URL (Aziz's instance)"
  type        = string
  default     = "https://192.168.60.100:55000"
}

variable "wazuh_api_user" {
  description = "Wazuh API username"
  type        = string
  default     = "admin"
  sensitive   = true
}

variable "wazuh_api_password" {
  description = "Wazuh API password"
  type        = string
  sensitive   = true
}

# Shuffle Integration
variable "shuffle_webhook_url" {
  description = "Shuffle webhook URL for enriched alerts"
  type        = string
  sensitive   = true
}

# MISP Integration
variable "misp_api_url" {
  description = "MISP API URL (Amine's instance)"
  type        = string
  default     = ""
}

variable "misp_api_key" {
  description = "MISP API key"
  type        = string
  default     = ""
  sensitive   = true
}

# ML Model Configuration
variable "ml_model_version" {
  description = "ML model version to deploy"
  type        = string
  default     = "v1.0.0"
}

variable "ml_inference_replicas" {
  description = "Number of ML inference API replicas"
  type        = number
  default     = 1
}
