
# IAM Rolle — Berechtigung für ECS Tasks
# ========================
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.project_name}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ========================
# ECS Cluster — Die Fabrik
# ========================
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"

  tags = {
    Name = "${var.project_name}-cluster"
  }
}

# ========================
# CloudWatch Log Gruppen — Protokollierung
# ========================
resource "aws_cloudwatch_log_group" "flask" {
  name              = "/ecs/${var.project_name}/flask"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "react" {
  name              = "/ecs/${var.project_name}/react"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "zap" {
  name              = "/ecs/${var.project_name}/zap"
  retention_in_days = 7
}
# ========================
# Service Discovery — Stabiler DNS-Name für Flask
# ========================
resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = "${var.project_name}.local"
  vpc         = var.vpc_id
  description = "Private DNS Namespace für WebSecScan Services"
}

resource "aws_service_discovery_service" "flask" {
  name = "flask"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}
# ========================
# Flask Task Definition — Bauplan für Flask Container
# ========================
resource "aws_ecs_task_definition" "flask" {
  family                   = "${var.project_name}-flask"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([{
    name  = "flask"
    image = var.flask_image

    portMappings = [{
      containerPort = 5001
      protocol      = "tcp"
    }]

    environment = [
      { name = "DB_HOST",     value = split(":", var.db_endpoint)[0] },
      { name = "DB_PORT",     value = "5432" },
      { name = "DB_NAME",     value = var.db_name },
      { name = "DB_USER",     value = var.db_username },
      { name = "DB_PASSWORD", value = var.db_password },
      { name = "FLASK_ENV",   value = "production" }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/${var.project_name}/flask"
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "flask"
      }
    }

    essential = true
  }])
}
resource "aws_ecs_service" "flask" {
  name            = "${var.project_name}-flask-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.flask.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.flask_sg_id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.flask.arn
  }

  depends_on = [aws_iam_role_policy_attachment.ecs_task_execution_role_policy]
}

# ========================
# React Task Definition — Bauplan für React Container
# ========================
resource "aws_ecs_task_definition" "react" {
  family                   = "${var.project_name}-react"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([{
    name  = "react"
    image = var.react_image

    portMappings = [{
      containerPort = 80
      protocol      = "tcp"
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/${var.project_name}/react"
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "react"
      }
    }

    essential = true
  }])
}

# ========================
# ZAP Task Definition — Bauplan für ZAP Scanner
# ========================
resource "aws_ecs_task_definition" "zap" {
  family                   = "${var.project_name}-zap"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([{
    name  = "zap"
    image = var.zap_image

    portMappings = [{
      containerPort = 8080
      protocol      = "tcp"
    }]

    command = [
      "zap.sh", "-daemon",
      "-host", "0.0.0.0",
      "-port", "8080",
      "-config", "api.disablekey=true",
      "-config", "api.addrs.addr.name=.*",
      "-config", "api.addrs.addr.regex=true"
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/${var.project_name}/zap"
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "zap"
      }
    }

    essential = true
  }])
}
# ========================
# React ECS Service — läuft 24/7
# ========================
resource "aws_ecs_service" "react" {
  name            = "${var.project_name}-react-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.react.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [var.react_sg_id]
    assign_public_ip = true
  }

  depends_on = [aws_iam_role_policy_attachment.ecs_task_execution_role_policy]
}