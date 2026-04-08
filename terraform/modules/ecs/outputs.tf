output "cluster_id" {
  description = "ECS Cluster ID"
  value       = aws_ecs_cluster.main.id
}

output "flask_service_name" {
  description = "Flask Service Name"
  value       = aws_ecs_service.flask.name
}

output "react_service_name" {
  description = "React Service Name"
  value       = aws_ecs_service.react.name
}