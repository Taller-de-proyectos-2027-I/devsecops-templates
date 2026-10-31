variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "modo_autenticacion" {
  description = "oidc (recomendado) o usuario_iam (si una SCP de la organización prohíbe crear proveedores OIDC)"
  type        = string
  default     = "oidc"
  validation {
    condition     = contains(["oidc", "usuario_iam"], var.modo_autenticacion)
    error_message = "modo_autenticacion debe ser \"oidc\" o \"usuario_iam\"."
  }
}

variable "github_org" {
  description = "Organización de GitHub (ej. taller-proyectos-usmp)"
  type        = string
}

variable "repos" {
  description = "Repositorios autorizados a desplegar (sin el prefijo de la organización)"
  type        = list(string)
}

variable "grupos" {
  description = "Identificadores de grupo; se crea un repositorio ECR taller/<grupo> por cada uno"
  type        = list(string)
}

variable "presupuesto_usd" {
  description = "Tope mensual de referencia para las alertas"
  type        = number
  default     = 50
}

variable "correos_alerta" {
  description = "Correos que reciben las alertas de presupuesto"
  type        = list(string)
}
