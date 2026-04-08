# ========================
# React Frontend Security Group
# ========================
resource "aws_security_group" "react" {
  name        = "${var.project_name}-react-sg"
  description = "Security group for React frontend"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-react-sg"
  }
}

# ========================
# Flask Backend Security Group
# ========================
resource "aws_security_group" "flask" {
  name        = "${var.project_name}-flask-sg"
  description = "Security group for Flask backend"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Allow traffic from React only"
    from_port       = 5001
    to_port         = 5001
    protocol        = "tcp"
    security_groups = [aws_security_group.react.id]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-flask-sg"
  }
}

# ========================
# PostgreSQL Security Group
# ========================
resource "aws_security_group" "postgres" {
  name        = "${var.project_name}-postgres-sg"
  description = "Security group for PostgreSQL database"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Allow traffic from Flask only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.flask.id]
  }

  tags = {
    Name = "${var.project_name}-postgres-sg"
  }
}

# ========================
# ZAP Scanner Security Group
# ========================
resource "aws_security_group" "zap" {
  name        = "${var.project_name}-zap-sg"
  description = "Security group for ZAP scanner"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Allow traffic from Flask only"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.flask.id]
  }

  egress {
    description = "Allow all outbound for scanning"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-zap-sg"
  }
}
