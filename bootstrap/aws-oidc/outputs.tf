output "aws_role_arn" {
  description = "Valor para la variable AWS_ROLE_ARN de cada repositorio"
  value       = aws_iam_role.pipeline.arn
}

output "tf_state_bucket" {
  description = "Valor para la variable TF_STATE_BUCKET"
  value       = aws_s3_bucket.tfstate.id
}

output "findings_bucket" {
  description = "Valor para la variable FINDINGS_BUCKET"
  value       = aws_s3_bucket.reportes.id
}

output "ecr_repositorios" {
  value = { for g, r in aws_ecr_repository.grupo : g => r.repository_url }
}

output "instance_profile_name" {
  description = "Valor de instance_profile_name en infra/staging.tfvars"
  value       = aws_iam_instance_profile.staging_ec2.name
}
