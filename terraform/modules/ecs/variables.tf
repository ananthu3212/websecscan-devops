variable "project_name" {
  description = "Projektname für die Benennung der Ressourcen"
  type        = string
}

variable "aws_region" {
  description = "AWS Region"
  type        = string
}

variable "flask_image" {
  description = "ECR URL für das Flask-Image"
  type        = string
}

variable "react_image" {
  description = "ECR URL für das React-Image"
  type        = string
}

variable "zap_image" {
  description = "ECR URL für das ZAP-Image"
  type        = string
}

variable "flask_sg_id" {
  description = "Security Group ID für Flask"
  type        = string
}

variable "react_sg_id" {
  description = "Security Group ID für React"
  type        = string
}

variable "zap_sg_id" {
  description = "Security Group ID für ZAP"
  type        = string
}

variable "public_subnet_ids" {
  description = "Öffentliche Subnet IDs für React und ZAP"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private Subnet IDs für Flask"
  type        = list(string)
}

variable "db_endpoint" {
  description = "RDS Endpunkt für Flask"
  type        = string
}

variable "db_name" {
  description = "Datenbankname"
  type        = string
}

variable "db_username" {
  description = "Datenbankbenutzername"
  type        = string
}

variable "db_password" {
  description = "Datenbankpasswort"
  type        = string
  sensitive   = true
}