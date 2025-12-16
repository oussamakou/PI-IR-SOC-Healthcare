variable "namespace" {
  description = "Kubernetes namespace for detection services"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "wazuh_api_url" {
  description = "Wazuh API URL"
  type        = string
}

variable "wazuh_api_user" {
  description = "Wazuh API user"
  type        = string
}

variable "wazuh_api_password" {
  description = "Wazuh API password"
  type        = string
  sensitive   = true
}

variable "shuffle_webhook_url" {
  description = "Shuffle webhook URL"
  type        = string
  sensitive   = true
}

variable "misp_api_url" {
  description = "MISP API URL"
  type        = string
}

variable "misp_api_key" {
  description = "MISP API key"
  type        = string
  sensitive   = true
}

# Secrets for integrations
resource "kubernetes_secret" "wazuh_credentials" {
  metadata {
    name      = "wazuh-credentials"
    namespace = var.namespace
  }

  data = {
    api_url  = var.wazuh_api_url
    username = var.wazuh_api_user
    password = var.wazuh_api_password
  }

  type = "Opaque"
}

resource "kubernetes_secret" "shuffle_credentials" {
  metadata {
    name      = "shuffle-credentials"
    namespace = var.namespace
  }

  data = {
    webhook_url = var.shuffle_webhook_url
  }

  type = "Opaque"
}

resource "kubernetes_secret" "misp_credentials" {
  count = var.misp_api_url != "" ? 1 : 0

  metadata {
    name      = "misp-credentials"
    namespace = var.namespace
  }

  data = {
    api_url = var.misp_api_url
    api_key = var.misp_api_key
  }

  type = "Opaque"
}

# ConfigMap for Sigma rules
resource "kubernetes_config_map" "sigma_rules" {
  metadata {
    name      = "sigma-rules"
    namespace = var.namespace
  }

  data = {
    "rules_path" = "/rules/sigma"
  }
}

# Wazuh Connector Deployment
resource "kubernetes_deployment" "wazuh_connector" {
  metadata {
    name      = "wazuh-connector"
    namespace = var.namespace
    labels = {
      app         = "wazuh-connector"
      component   = "integration"
      environment = var.environment
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "wazuh-connector"
      }
    }

    template {
      metadata {
        labels = {
          app = "wazuh-connector"
        }
      }

      spec {
        container {
          name  = "wazuh-connector"
          image = "python:3.10-slim"
          
          command = ["/bin/sh", "-c"]
          args    = ["pip install requests && python /app/main.py"]

          env {
            name = "WAZUH_API_URL"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.wazuh_credentials.metadata[0].name
                key  = "api_url"
              }
            }
          }

          env {
            name = "WAZUH_USER"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.wazuh_credentials.metadata[0].name
                key  = "username"
              }
            }
          }

          env {
            name = "WAZUH_PASS"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.wazuh_credentials.metadata[0].name
                key  = "password"
              }
            }
          }

          env {
            name = "SHUFFLE_WEBHOOK_URL"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.shuffle_credentials.metadata[0].name
                key  = "webhook_url"
              }
            }
          }

          env {
            name  = "ML_API_URL"
            value = "http://ml-inference:8000"
          }

          volume_mount {
            name       = "app-code"
            mount_path = "/app"
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }
        }

        volume {
          name = "app-code"
          empty_dir {}
        }
      }
    }
  }
}

# ML Inference API Deployment
resource "kubernetes_deployment" "ml_inference" {
  metadata {
    name      = "ml-inference"
    namespace = var.namespace
    labels = {
      app         = "ml-inference"
      component   = "ml-engine"
      environment = var.environment
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "ml-inference"
      }
    }

    template {
      metadata {
        labels = {
          app = "ml-inference"
        }
      }

      spec {
        container {
          name  = "ml-inference"
          image = "python:3.10-slim"
          
          command = ["/bin/sh", "-c"]
          args    = ["pip install fastapi uvicorn scikit-learn pandas numpy joblib prometheus-client pydantic && uvicorn api:app --host 0.0.0.0 --port 8000"]

          port {
            container_port = 8000
            name           = "http"
          }

          volume_mount {
            name       = "ml-models"
            mount_path = "/models"
          }

          volume_mount {
            name       = "app-code"
            mount_path = "/app"
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = 10
            period_seconds        = 5
          }

          resources {
            requests = {
              cpu    = "500m"
              memory = "1Gi"
            }
            limits = {
              cpu    = "2000m"
              memory = "4Gi"
            }
          }
        }

        volume {
          name = "ml-models"
          empty_dir {}
        }

        volume {
          name = "app-code"
          empty_dir {}
        }
      }
    }
  }
}

# ML Inference Service
resource "kubernetes_service" "ml_inference" {
  metadata {
    name      = "ml-inference"
    namespace = var.namespace
  }

  spec {
    selector = {
      app = "ml-inference"
    }

    port {
      port        = 8000
      target_port = 8000
      protocol    = "TCP"
      name        = "http"
    }

    type = "ClusterIP"
  }
}

# Sigma Converter Deployment
resource "kubernetes_deployment" "sigma_converter" {
  metadata {
    name      = "sigma-converter"
    namespace = var.namespace
    labels = {
      app         = "sigma-converter"
      component   = "detection-rules"
      environment = var.environment
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "sigma-converter"
      }
    }

    template {
      metadata {
        labels = {
          app = "sigma-converter"
        }
      }

      spec {
        container {
          name  = "sigma-converter"
          image = "python:3.10-slim"
          
          command = ["/bin/sh", "-c"]
          args    = ["pip install pysigma pysigma-backend-wazuh && while true; do sleep 3600; done"]

          volume_mount {
            name       = "sigma-rules"
            mount_path = "/rules"
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "256Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }
        }

        volume {
          name = "sigma-rules"
          config_map {
            name = kubernetes_config_map.sigma_rules.metadata[0].name
          }
        }
      }
    }
  }
}

# Outputs
output "wazuh_connector_deployment" {
  value       = kubernetes_deployment.wazuh_connector.metadata[0].name
  description = "Wazuh connector deployment name"
}

output "ml_inference_service" {
  value       = kubernetes_service.ml_inference.metadata[0].name
  description = "ML inference service name"
}

output "sigma_converter_deployment" {
  value       = kubernetes_deployment.sigma_converter.metadata[0].name
  description = "Sigma converter deployment name"
}
