terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ========================
# Networking Module
# ========================
module "networking" {
  source       = "./modules/networking"
  project_name = var.project_name
  aws_region   = var.aws_region
}

# ========================
# Security Groups Module
# ========================
module "security_groups" {
  source       = "./modules/security-groups"
  project_name = var.project_name
  vpc_id       = module.networking.vpc_id
}

module "rds" {
  source               = "./modules/rds"
  project_name         = var.project_name
  db_name              = var.db_name
  db_username          = var.db_username
  db_password          = var.db_password
  db_subnet_ids        = module.networking.private_subnet_ids
  db_security_group_id = module.security_groups.postgres_sg_id
}

module "ecr" {
  source       = "./modules/ecr"
  project_name = var.project_name
}
module "ecs" {
  source             = "./modules/ecs"
  project_name       = var.project_name
  aws_region         = var.aws_region
  flask_image        = module.ecr.flask_repository_url
  react_image        = module.ecr.react_repository_url
  zap_image          = module.ecr.zap_repository_url
  flask_sg_id        = module.security_groups.flask_sg_id
  react_sg_id        = module.security_groups.react_sg_id
  zap_sg_id          = module.security_groups.zap_sg_id
  public_subnet_ids  = module.networking.public_subnet_ids
  private_subnet_ids = module.networking.private_subnet_ids
  db_endpoint        = module.rds.db_endpoint
  db_name            = var.db_name
  db_username        = var.db_username
  db_password        = var.db_password
}