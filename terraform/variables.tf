variable "aws_region" {
  description = "AWS region where everything will be deployed"
  type        = string
  default     = "eu-central-1"
}

variable "project_name" {
  description = "Name of the project - used to name all AWS resources"
  type        = string
  default     = "websecscan"
}

variable "environment" {
  description = "Environment name - dev, staging, or production"
  type        = string
  default     = "dev"
}

variable "db_name" {
  description = "PostgreSQL database name"
  type        = string
  default     = "websecscan_db"
}

variable "db_username" {
  description = "PostgreSQL master username"
  type        = string
  default     = "websecscan_admin"
}

variable "db_password" {
  description = "PostgreSQL master password - keep this secret"
  type        = string
  sensitive   = true
}