variable "aws_region" {
  type    = string
  default = "us-east-2"
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
