variable "nombre" {
  description = "Prefijo de recursos (identificador del grupo, ej. g01)"
  type        = string
}

variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "image_uri" {
  description = "URI de la imagen en ECR (la inyecta el pipeline)"
  type        = string
}

variable "app_port" {
  type    = number
  default = 8080
}

variable "instance_type" {
  description = "Tamaño de la instancia; t3.small da memoria suficiente para Spring Boot"
  type        = string
  default     = "t3.small"
}

variable "instance_profile_name" {
  description = "Perfil de instancia creado en el bootstrap (solo lectura de ECR)"
  type        = string
}

variable "allowed_cidrs" {
  description = "Orígenes permitidos hacia la app de staging"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
