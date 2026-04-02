output "flask_repository_url" {
  description = "ECR URL für Flask-Image"
  value       = aws_ecr_repository.flask.repository_url
}

output "react_repository_url" {
  description = "ECR URL für React-Image"
  value       = aws_ecr_repository.react.repository_url
}

output "zap_repository_url" {
  description = "ECR URL für ZAP-Image"
  value       = aws_ecr_repository.zap.repository_url
}

output "registry_id" {
  description = "AWS Account ID für ECR Registry"
  value       = aws_ecr_repository.flask.registry_id
}