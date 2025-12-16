terraform {
  required_version = ">= 1.0"
  
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }

  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}

# Core namespace for detection pipeline
resource "kubernetes_namespace" "detection_pipeline" {
  metadata {
    name = "detection-pipeline"
    labels = {
      name        = "detection-pipeline"
      environment = var.environment
      managed-by  = "terraform"
    }
  }
}

# Namespace for ArgoCD
resource "kubernetes_namespace" "argocd" {
  metadata {
    name = "argocd"
    labels = {
      name       = "argocd"
      managed-by = "terraform"
    }
  }
}

# Namespace for monitoring
resource "kubernetes_namespace" "monitoring" {
  metadata {
    name = "monitoring"
    labels = {
      name       = "monitoring"
      managed-by = "terraform"
    }
  }
}

# Deploy detection services module
module "detection_services" {
  source = "./modules/detection-services"
  
  namespace   = kubernetes_namespace.detection_pipeline.metadata[0].name
  environment = var.environment
  
  wazuh_api_url      = var.wazuh_api_url
  wazuh_api_user     = var.wazuh_api_user
  wazuh_api_password = var.wazuh_api_password
  
  shuffle_webhook_url = var.shuffle_webhook_url
  misp_api_url        = var.misp_api_url
  misp_api_key        = var.misp_api_key
}

# Deploy monitoring stack
module "monitoring" {
  source = "./modules/monitoring"
  
  namespace   = kubernetes_namespace.monitoring.metadata[0].name
  environment = var.environment
}

# Outputs
output "detection_pipeline_namespace" {
  value       = kubernetes_namespace.detection_pipeline.metadata[0].name
  description = "Detection pipeline namespace"
}

output "argocd_namespace" {
  value       = kubernetes_namespace.argocd.metadata[0].name
  description = "ArgoCD namespace"
}

output "monitoring_namespace" {
  value       = kubernetes_namespace.monitoring.metadata[0].name
  description = "Monitoring namespace"
}
