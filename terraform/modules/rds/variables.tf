variable "project_name" {
  description = "Project name for labeling"
  type        = string
}

variable "db_name" {
  description = "PostgreSQL database name"
  type        = string
}

variable "db_username" {
  description = "PostgreSQL master username"
  type        = string
}

variable "db_password" {
  description = "PostgreSQL master password"
  type        = string
  sensitive   = true
}

variable "db_subnet_ids" {
  description = "Private subnet IDs for database"
  type        = list(string)
}

variable "db_security_group_id" {
  description = "Security group ID for database"
  type        = string
}