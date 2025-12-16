variable "namespace" {
  description = "Kubernetes namespace for monitoring"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

# Prometheus Deployment
resource "kubernetes_deployment" "prometheus" {
  metadata {
    name      = "prometheus"
    namespace = var.namespace
    labels = {
      app         = "prometheus"
      component   = "monitoring"
      environment = var.environment
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "prometheus"
      }
    }

    template {
      metadata {
        labels = {
          app = "prometheus"
        }
      }

      spec {
        container {
          name  = "prometheus"
          image = "prom/prometheus:latest"

          port {
            container_port = 9090
            name           = "http"
          }

          volume_mount {
            name       = "prometheus-config"
            mount_path = "/etc/prometheus"
          }

          volume_mount {
            name       = "prometheus-data"
            mount_path = "/prometheus"
          }

          resources {
            requests = {
              cpu    = "500m"
              memory = "1Gi"
            }
            limits = {
              cpu    = "1000m"
              memory = "2Gi"
            }
          }
        }

        volume {
          name = "prometheus-config"
          config_map {
            name = kubernetes_config_map.prometheus_config.metadata[0].name
          }
        }

        volume {
          name = "prometheus-data"
          empty_dir {}
        }
      }
    }
  }
}

# Prometheus Service
resource "kubernetes_service" "prometheus" {
  metadata {
    name      = "prometheus"
    namespace = var.namespace
  }

  spec {
    selector = {
      app = "prometheus"
    }

    port {
      port        = 9090
      target_port = 9090
      protocol    = "TCP"
      name        = "http"
    }

    type = "ClusterIP"
  }
}

# Prometheus ConfigMap
resource "kubernetes_config_map" "prometheus_config" {
  metadata {
    name      = "prometheus-config"
    namespace = var.namespace
  }

  data = {
    "prometheus.yml" = <<-EOT
      global:
        scrape_interval: 15s
        evaluation_interval: 15s

      scrape_configs:
        - job_name: 'ml-inference'
          static_configs:
            - targets: ['ml-inference.detection-pipeline:8000']
          metrics_path: '/metrics'

        - job_name: 'kubernetes-pods'
          kubernetes_sd_configs:
            - role: pod
          relabel_configs:
            - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
              action: keep
              regex: true
    EOT
  }
}

# Grafana Deployment
resource "kubernetes_deployment" "grafana" {
  metadata {
    name      = "grafana"
    namespace = var.namespace
    labels = {
      app         = "grafana"
      component   = "monitoring"
      environment = var.environment
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "grafana"
      }
    }

    template {
      metadata {
        labels = {
          app = "grafana"
        }
      }

      spec {
        container {
          name  = "grafana"
          image = "grafana/grafana:latest"

          port {
            container_port = 3000
            name           = "http"
          }

          env {
            name  = "GF_SECURITY_ADMIN_PASSWORD"
            value = "admin"
          }

          env {
            name  = "GF_INSTALL_PLUGINS"
            value = "grafana-piechart-panel"
          }

          volume_mount {
            name       = "grafana-data"
            mount_path = "/var/lib/grafana"
          }

          resources {
            requests = {
              cpu    = "250m"
              memory = "512Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "1Gi"
            }
          }
        }

        volume {
          name = "grafana-data"
          empty_dir {}
        }
      }
    }
  }
}

# Grafana Service
resource "kubernetes_service" "grafana" {
  metadata {
    name      = "grafana"
    namespace = var.namespace
  }

  spec {
    selector = {
      app = "grafana"
    }

    port {
      port        = 3000
      target_port = 3000
      protocol    = "TCP"
      name        = "http"
    }

    type = "NodePort"
  }
}

# Outputs
output "prometheus_service" {
  value       = kubernetes_service.prometheus.metadata[0].name
  description = "Prometheus service name"
}

output "grafana_service" {
  value       = kubernetes_service.grafana.metadata[0].name
  description = "Grafana service name"
}
