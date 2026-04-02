output "react_sg_id" {
  description = "Security group ID for React frontend"
  value       = aws_security_group.react.id
}

output "flask_sg_id" {
  description = "Security group ID for Flask backend"
  value       = aws_security_group.flask.id
}

output "postgres_sg_id" {
  description = "Security group ID for PostgreSQL"
  value       = aws_security_group.postgres.id
}

output "zap_sg_id" {
  description = "Security group ID for ZAP scanner"
  value       = aws_security_group.zap.id
}
