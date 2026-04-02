# Flask Backend Repository
resource "aws_ecr_repository" "flask" {
  name                 = "${var.project_name}-flask"
  image_tag_mutability = "MUTABLE"
 force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${var.project_name}-flask"
  }
}

# React Frontend Repository
resource "aws_ecr_repository" "react" {
  name                 = "${var.project_name}-react"
  image_tag_mutability = "MUTABLE"
   force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${var.project_name}-react"
  }
}

# ZAP Scanner Repository
resource "aws_ecr_repository" "zap" {
  name                 = "${var.project_name}-zap"
  image_tag_mutability = "MUTABLE"
   force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${var.project_name}-zap"
  }
}

# Lifecycle policy — automatically delete old images to save storage
resource "aws_ecr_lifecycle_policy" "flask" {
  repository = aws_ecr_repository.flask.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Behalte nur die letzten 5 Images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = {
        type = "expire"
      }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "react" {
  repository = aws_ecr_repository.react.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Behalte nur die letzten 5 Images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = {
        type = "expire"
      }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "zap" {
  repository = aws_ecr_repository.zap.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Behalte nur die letzten 5 Images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = {
        type = "expire"
      }
    }]
  })
}