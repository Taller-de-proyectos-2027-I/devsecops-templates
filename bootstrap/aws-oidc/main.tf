# -----------------------------------------------------------------------------
# BOOTSTRAP (se ejecuta UNA vez, localmente, por el rol DevSecOps)
# Crea la base de confianza entre GitHub Actions y la cuenta AWS:
#   - Rol que asume el pipeline, por uno de dos modos (var.modo_autenticacion):
#       oidc        -> proveedor OIDC de GitHub, sin llaves (recomendado)
#       usuario_iam -> usuario IAM sin permisos propios que solo puede asumir
#                      el rol; para cuentas cuya SCP prohíbe crear proveedores OIDC
#   - Bucket del estado de Terraform y bucket de reportes
#   - Repositorios ECR por grupo
#   - Rol/perfil de instancia para el staging (solo lectura de ECR)
#   - Presupuesto con alertas para no agotar los créditos
# -----------------------------------------------------------------------------
terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Proyecto = "taller-proyectos"
      Gestion  = "terraform-devsecops-bootstrap"
    }
  }
}

data "aws_caller_identity" "actual" {}

locals {
  cuenta = data.aws_caller_identity.actual.account_id
  sujetos = flatten([
    for r in var.repos : [
      "repo:${var.github_org}/${r}:ref:refs/heads/main",
      "repo:${var.github_org}/${r}:environment:staging",
      "repo:${var.github_org}/${r}:environment:aprobacion-release",
    ]
  ])
}

# --- Confianza GitHub -> AWS -----------------------------------------------------
locals {
  usar_oidc    = var.modo_autenticacion == "oidc"
  usar_usuario = var.modo_autenticacion == "usuario_iam"
}

# Modo oidc: GitHub obtiene credenciales temporales sin llaves guardadas
resource "aws_iam_openid_connect_provider" "github" {
  count           = local.usar_oidc ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]
}

# Modo usuario_iam: identidad mínima cuyas llaves viven solo en los environments
# protegidos de GitHub. No tiene permisos propios: únicamente puede asumir el rol.
resource "aws_iam_user" "pipeline" {
  # checkov:skip=CKV_AWS_273:La cuenta prohibe OIDC por SCP; el usuario solo puede asumir el rol del pipeline
  count = local.usar_usuario ? 1 : 0
  name  = "devsecops-pipeline"
  tags = {
    Proposito = "GitHub Actions - solo sts:AssumeRole"
  }
}

data "aws_iam_policy_document" "usuario_solo_asumir" {
  statement {
    sid       = "SoloAsumirRolPipeline"
    actions   = ["sts:AssumeRole", "sts:TagSession"]
    resources = ["arn:aws:iam::${local.cuenta}:role/devsecops-github-actions"]
  }
}

resource "aws_iam_user_policy" "pipeline" {
  # checkov:skip=CKV_AWS_40:Politica minima (solo sts:AssumeRole) sobre un unico usuario tecnico; un grupo no aporta control adicional
  count  = local.usar_usuario ? 1 : 0
  name   = "solo-asumir-rol-pipeline"
  user   = aws_iam_user.pipeline[0].name
  policy = data.aws_iam_policy_document.usuario_solo_asumir.json
}

data "aws_iam_policy_document" "confianza" {
  dynamic "statement" {
    for_each = local.usar_oidc ? [1] : []
    content {
      sid     = "GitHubOIDC"
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = [aws_iam_openid_connect_provider.github[0].arn]
      }
      condition {
        test     = "StringEquals"
        variable = "token.actions.githubusercontent.com:aud"
        values   = ["sts.amazonaws.com"]
      }
      # Solo la rama main y los environments protegidos pueden asumir el rol;
      # un pull request NUNCA obtiene credenciales de AWS.
      condition {
        test     = "StringLike"
        variable = "token.actions.githubusercontent.com:sub"
        values   = local.sujetos
      }
    }
  }

  dynamic "statement" {
    for_each = local.usar_usuario ? [1] : []
    content {
      sid     = "UsuarioPipeline"
      actions = ["sts:AssumeRole", "sts:TagSession"]
      principals {
        type        = "AWS"
        identifiers = [aws_iam_user.pipeline[0].arn]
      }
    }
  }
}

resource "aws_iam_role" "pipeline" {
  name                 = "devsecops-github-actions"
  assume_role_policy   = data.aws_iam_policy_document.confianza.json
  max_session_duration = 3600
}

# --- Permisos mínimos del pipeline ---------------------------------------------
data "aws_iam_policy_document" "pipeline" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "EcrPushPull"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart",
      "ecr:DescribeImages",
    ]
    resources = [for r in aws_ecr_repository.grupo : r.arn]
  }
  statement {
    sid = "StagingEc2"
    actions = [
      "ec2:RunInstances", "ec2:TerminateInstances", "ec2:Describe*", "ec2:CreateTags",
      "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup", "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifyInstanceAttribute",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }
  statement {
    sid       = "AmiPublica"
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:aws:ssm:${var.aws_region}::parameter/aws/service/ami-amazon-linux-latest/*"]
  }
  statement {
    sid       = "PasarSoloRolStaging"
    actions   = ["iam:PassRole", "iam:GetInstanceProfile"]
    resources = [aws_iam_role.staging_ec2.arn, aws_iam_instance_profile.staging_ec2.arn]
  }
  statement {
    sid       = "EstadoTerraform"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.tfstate.arn]
  }
  statement {
    sid       = "EstadoTerraformObjetos"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.tfstate.arn}/*"]
  }
  statement {
    sid       = "PublicarReportes"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.reportes.arn}/*"]
  }
}

resource "aws_iam_role_policy" "pipeline" {
  name   = "devsecops-pipeline-minimo"
  role   = aws_iam_role.pipeline.id
  policy = data.aws_iam_policy_document.pipeline.json
}

# --- Rol de la instancia de staging (solo puede leer imágenes) ----------------
data "aws_iam_policy_document" "ec2_confianza" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "staging_ec2" {
  name               = "devsecops-staging-ec2"
  assume_role_policy = data.aws_iam_policy_document.ec2_confianza.json
}

resource "aws_iam_role_policy_attachment" "staging_ecr" {
  role       = aws_iam_role.staging_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_instance_profile" "staging_ec2" {
  name = "devsecops-staging-ec2"
  role = aws_iam_role.staging_ec2.name
}

# --- Repositorios ECR por grupo -----------------------------------------------
resource "aws_ecr_repository" "grupo" {
  # checkov:skip=CKV_AWS_136:Cifrado AES256 administrado por AWS; KMS propio tiene costo mensual
  for_each             = toset(var.grupos)
  name                 = "taller/${each.value}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "grupo" {
  for_each   = aws_ecr_repository.grupo
  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Conservar solo las 15 imagenes mas recientes (ahorro de almacenamiento)"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 15 }
      action       = { type = "expire" }
    }]
  })
}

# --- Buckets S3: estado de Terraform y reportes --------------------------------
resource "aws_s3_bucket" "tfstate" {
  # checkov:skip=CKV_AWS_144:Replicacion entre regiones innecesaria en contexto academico
  # checkov:skip=CKV_AWS_145:Cifrado SSE-S3; KMS propio tiene costo
  # checkov:skip=CKV2_AWS_62:Sin notificaciones de eventos
  # checkov:skip=CKV_AWS_18:Sin access logging para no generar costo adicional
  bucket = "devsecops-tfstate-${local.cuenta}"
}

resource "aws_s3_bucket" "reportes" {
  # checkov:skip=CKV_AWS_144:Replicacion entre regiones innecesaria en contexto academico
  # checkov:skip=CKV_AWS_145:Cifrado SSE-S3; KMS propio tiene costo
  # checkov:skip=CKV2_AWS_62:Sin notificaciones de eventos
  # checkov:skip=CKV_AWS_18:Sin access logging para no generar costo adicional
  bucket = "devsecops-reportes-${local.cuenta}"
}

resource "aws_s3_bucket_versioning" "buckets" {
  for_each = { tfstate = aws_s3_bucket.tfstate.id, reportes = aws_s3_bucket.reportes.id }
  bucket   = each.value
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "buckets" {
  for_each = { tfstate = aws_s3_bucket.tfstate.id, reportes = aws_s3_bucket.reportes.id }
  bucket   = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "buckets" {
  for_each                = { tfstate = aws_s3_bucket.tfstate.id, reportes = aws_s3_bucket.reportes.id }
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "buckets" {
  for_each = { tfstate = aws_s3_bucket.tfstate.id, reportes = aws_s3_bucket.reportes.id }
  bucket   = each.value
  rule {
    id     = "limpiar-versiones-antiguas"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# --- Presupuesto con alertas (cuida los créditos) -------------------------------
resource "aws_budgets_budget" "creditos" {
  name         = "taller-devsecops-creditos"
  budget_type  = "COST"
  limit_amount = tostring(var.presupuesto_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Excluir créditos: así el presupuesto mide el consumo real que se descuenta de ellos
  cost_types {
    include_credit = false
    include_refund = false
  }

  dynamic "notification" {
    for_each = [50, 80, 100]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = var.correos_alerta
    }
  }
}
