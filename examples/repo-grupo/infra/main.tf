# -----------------------------------------------------------------------------
# Staging efímero para DAST: una instancia EC2 pequeña que ejecuta el contenedor
# publicado en ECR. Sin ALB ni NAT Gateway para cuidar los créditos.
# El pipeline lo crea antes del DAST y lo destruye al terminar.
# -----------------------------------------------------------------------------
terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # bucket, key, region y use_lockfile los inyecta el pipeline
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Proyecto  = "taller-proyectos"
      Grupo     = var.nombre
      Entorno   = "staging"
      Gestion   = "terraform-devsecops"
    }
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_security_group" "app" {
  name        = "${var.nombre}-staging-app"
  description = "Acceso HTTP a la aplicacion de staging para pruebas DAST"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Puerto de la aplicacion (DAST desde runners de GitHub)"
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  egress {
    description = "Salida HTTPS para descargar la imagen desde ECR"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app" {
  # checkov:skip=CKV_AWS_88:Staging efimero con IP publica para que el DAST alcance la app; se destruye al terminar
  # checkov:skip=CKV_AWS_126:Monitoreo detallado tiene costo y el entorno vive minutos
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.instance_type
  iam_instance_profile        = var.instance_profile_name
  vpc_security_group_ids      = [aws_security_group.app.id]
  associate_public_ip_address = true
  ebs_optimized               = true
  monitoring                  = false

  metadata_options {
    http_tokens                 = "required" # IMDSv2 obligatorio
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    volume_size = 30
    volume_type = "gp3"
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    image_uri  = var.image_uri
    app_port   = var.app_port
    aws_region = var.aws_region
    registry   = split("/", var.image_uri)[0]
  })

  tags = {
    Name = "${var.nombre}-staging"
  }
}
