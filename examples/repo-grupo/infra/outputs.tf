output "app_url" {
  description = "URL base que usa el DAST"
  value       = "http://${aws_instance.app.public_dns}:${var.app_port}"
}
