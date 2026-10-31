# devsecops-templates

Pipeline DevSecOps reutilizable para los proyectos Java (Spring Boot) del **Taller de Proyectos — USMP**, con despliegue a AWS.
Lo mantiene el rol **DevSecOps**; cada grupo solo lo invoca desde su repositorio y lo adapta con parámetros.

```
                 PULL REQUEST                                 PUSH A main
┌──────────────────────────────────────────┐   ┌───────────────────────────────────────────────────────────┐
│ 1. INTEGRACIÓN (en paralelo)             │   │ 2. BUILD           3. STAGING AWS      4. PRUEBAS         │
│   SEC · Secretos ........ Gitleaks       │   │   docker build ─►  terraform apply ─►  SEC · DAST (ZAP)   │
│   SEC · SAST Java ....... SpotBugs+FSB   │──►│   Trivy imagen     EC2 efímera         baseline + API     │
│   SEC · SAST ............ Semgrep CE     │   │   [gate imagen]    health check        terraform destroy  │
│   SEC · Dependencias .... Trivy + SBOM   │   │   push a ECR                                              │
│   SEC · IaC/Dockerfile .. Checkov        │   ├───────────────────────────────────────────────────────────┤
│           │                              │   │ 5. REPORTE: hallazgos.json + metricas.json (+ S3)         │
│   [GATE DE INTEGRACIÓN] bloquea el merge │   │ 6. RELEASE: aprobación DevSecOps → imagen approved-<sha>  │
└──────────────────────────────────────────┘   └───────────────────────────────────────────────────────────┘
```

- En un **PR** corre solo la integración. Si el gate falla, no se puede hacer merge.
- En un **push a `main`** corre todo. Una imagen vulnerable no se publica, y staging se destruye al terminar el DAST.
- Un PR **nunca** obtiene credenciales de AWS. El rol OIDC solo confía en `main` y en los *environments* protegidos.
- Todas las herramientas son open source y corren en contenedores o con `pip`. Por eso el mismo diseño se puede portar a otro orquestador sin rehacerlo.

## Contenido

| Ruta | Qué es |
|---|---|
| `.github/workflows/devsecops-pipeline.yml` | Pipeline reutilizable (`workflow_call`) |
| `scripts/normalize_gate.py` | Normaliza los reportes al contrato de datos, aplica supresiones, evalúa el gate y calcula métricas |
| `schema/hallazgo.schema.json` | Contrato de datos v1.0 (para líderes, el agente de IA y la investigación) |
| `policies/spotbugs-security-include.xml` | Filtro de SpotBugs: solo la categoría SECURITY |
| `bootstrap/aws-oidc/` | Terraform que se ejecuta **una vez**: OIDC, rol del pipeline, buckets, ECR, presupuesto |
| `examples/repo-grupo/` | Lo que va en el repo de cada grupo: workflow, `Dockerfile`, `infra/` y `.devsecops/suppressions.yml` |

---

## Primer paso: preparar la base (en este orden)

### 1. Organización de GitHub
1. Crear el repo **`devsecops-templates`** como **público**, subir este contenido y crear el tag `v1`.
   Los grupos lo invocan con `@v1`, así que un cambio en `main` no les rompe el pipeline a mitad de sprint.
2. **Settings → Member privileges:** permiso base `Read`.
3. **Teams:** `devsecops` (Jair, Víctor) y por grupo `gXX-arquitectos`, `gXX-fullstack`, `gXX-ciberseguridad`.
4. **Settings → Actions → General:** permitir solo acciones de la org y de creadores verificados (`actions/*`, `aws-actions/*`, `hashicorp/*`).
5. **Settings → Repository → Rulesets** (a nivel de organización, para todos los repos `g*`), sobre la rama `main`:
   - exigir pull request con 1 aprobación;
   - bloquear *force push* y borrado;
   - exigir el *status check* **`devsecops / Gate de integración`**.

### 2. Cuenta AWS (con los créditos)
1. Proteger la cuenta raíz con MFA y crear un usuario administrador temporal **solo** para el bootstrap.
2. Preparar la PC desde donde se ejecuta el bootstrap (una sola vez):
   - Instalar **AWS CLI v2** y **Terraform** (≥ 1.10).
   - Iniciar sesión sin access keys: `aws login --region us-east-2` y verificar con `aws sts get-caller-identity`.
   - La región de la cuenta es **us-east-2 (Ohio)**; todos los valores por defecto del pipeline la usan.
3. Ejecutar el bootstrap:
   ```bash
   cd bootstrap/aws-oidc
   cp terraform.tfvars.example terraform.tfvars   # completar org, repos, grupos y correos
   terraform init && terraform apply
   ```
4. Con los *outputs*, crear las **variables de organización** (Settings → Secrets and variables → Actions → Variables): `AWS_ROLE_ARN`, `TF_STATE_BUCKET` y `FINDINGS_BUCKET`. No son secretos, porque con OIDC no hay llaves que guardar.
5. Si se creó un usuario con access keys para el bootstrap, eliminarlas.

### 3. Repositorio de cada grupo
1. Crear `gXX-sistema` y copiar el contenido de `examples/repo-grupo/`.
2. Ajustar `grupo`, `ecr-repository` e `infra/staging.tfvars`.
3. En **Settings → Environments** crear:
   - `staging`: sin revisores, despliegue permitido solo desde `main`;
   - `aprobacion-release`: *required reviewers* = equipo `devsecops`.
4. Crear la variable de repo `SPRINT_ACTUAL` (ej. `S1`). La actualiza el líder en cada sprint.
5. Abrir un PR de prueba y revisar el resumen del gate en la pestaña *Actions*.

---

## Adaptación por grupo (inputs principales)

| Input | Por defecto | Para qué |
|---|---|---|
| `app-dir` / `build-tool` / `java-version` | `.` / `maven` / `21` | Ubicación y tipo de proyecto (también soporta `gradle`) |
| `fail-on` | `HIGH` | Severidad mínima que bloquea (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`) |
| `enable-gitleaks`, `enable-spotbugs`, `enable-semgrep`, `enable-trivy-fs`, `enable-checkov`, `enable-dast` | `true` | Encender o apagar herramientas |
| `semgrep-configs` | `p/java p/owasp-top-ten` | Conjuntos de reglas de Semgrep |
| `iac-dir` / `dockerfile` | `infra` / `Dockerfile` | Qué escanea Checkov y qué se construye |
| `deploy` | `false` | Activa build, ECR, staging y DAST (usarlo solo en push a `main`) |
| `ephemeral-staging` | `true` | Destruye staging al terminar el DAST |
| `health-path` / `openapi-path` | `/actuator/health` / `/v3/api-docs` | Espera de arranque y API scan de ZAP |
| `promote` | `false` | Pide aprobación del rol DevSecOps y marca la imagen `approved-<sha>` |
| `templates-ref` | `main` | Versión de scripts y políticas; debe coincidir con el `@v1` del `uses:` |

Un microservicio adicional se cubre con un segundo job en el workflow del grupo que llame al mismo pipeline con otro `app-dir`, `dockerfile` y `ecr-repository`.

## Política del gate y aceptación de riesgos

- **Bloquea:** hallazgos abiertos con severidad ≥ `fail-on`. Hay tres gates: integración (merge), imagen (publicación en ECR) y DAST (promoción).
- **Si una herramienta falla al ejecutarse,** el gate de integración también falla. No se aprueba con datos incompletos.
- **Supresión justificada:** se agrega en `.devsecops/suppressions.yml`, con `id` o `regla`, `justificacion`, `aprobado_por` y `expira`.
  - Una entrada sin aprobador o vencida se ignora y genera un aviso.
  - El cambio pasa por PR, así que el rol de Ciberseguridad lo revisa.
- **Supresiones nativas** (`checkov:skip=ID:motivo`, `nosemgrep`, `.trivyignore`, `.gitleaksignore`): se registran como `suprimido` y conservan su justificación.
- **Severidad de Checkov:** sin la plataforma comercial, Checkov no informa severidad. Todo control fallido se trata como `HIGH`, es decir, se corrige o se justifica. El Terraform de ejemplo pasa sin fallos.

## Contrato de datos (insumo para líderes y para el agente de IA)

Cada ejecución publica el artefacto **`devsecops-reporte`** (90 días) con:
- **`hallazgos.json`:** contexto de la ejecución, resultado del gate y la lista de hallazgos normalizados (`herramienta`, `categoria`, `etapa`, `severidad`, `cwe`, `cve`, `ubicacion`, `estado`, `supresion`, `bloquea`, `fecha_commit`, `fecha_deteccion`…). El esquema completo está en `schema/hallazgo.schema.json`.
- **`metricas.json`:** KLOC, conteo por severidad y categoría, densidad, tiempo commit→detección y overhead por job.
- **`sbom.cdx.json`:** inventario de dependencias (CycloneDX).

En la rama principal, si se define `findings-bucket`, también se copia a `s3://<bucket>/<grupo>/<fecha>/<run_id>/`.

El agente puede leer los artefactos con la API de GitHub o los objetos de S3. El campo `id` es una huella estable: permite seguir un mismo hallazgo entre ejecuciones y saber cuándo apareció y cuándo se corrigió.

## Relación con las variables de la investigación

| Variable | Fuente en el pipeline |
|---|---|
| Densidad de vulnerabilidades | `metricas.json → densidad_vulnerabilidades` (abiertos / KLOC de `src/main`) |
| Tiempo de detección | `fecha_deteccion − fecha_commit` por hallazgo; primera aparición por `id` entre ejecuciones |
| Overhead | `metricas.json → overhead`: suma del tiempo de los jobs `SEC ·` sobre el total (tiempo de cómputo, no tiempo de pared) |
| Tasa de detección IA | Comparar los hallazgos del agente/IA contra los `id` de las herramientas tradicionales |
| Nivel DSOMM | Auditoría de la configuración: gates, OIDC, SBOM, IaC, DAST, supresiones con aprobación |

## Costos esperados con créditos

- **Staging efímero** (`t3.small`, unos 15 min por despliegue): centavos por ejecución.
- **ECR:** se conservan las últimas 15 imágenes.
- **S3:** el estado y los reportes son pocos MB.
- **Sin ALB, sin NAT Gateway y sin KMS propio,** que son los costos fijos que más rápido consumen créditos.
- **AWS Budgets** avisa por correo al 50 %, 80 % y 100 % del tope definido, excluyendo los créditos para ver el consumo real.

## Límites conocidos

- Las versiones de las herramientas están fijadas en el bloque `env` del pipeline. Conviene revisarlas al inicio de cada ciclo.
- Para mayor seguridad de la cadena de suministro, fije las acciones por SHA (`actions/checkout@<sha>`).
- En Gradle, SpotBugs corre sin *auxclasspath*. Funciona, pero es algo menos preciso que en Maven.
- Code Scanning (la carga de SARIF en la pestaña *Security*) solo es gratuito en repositorios públicos. Por eso el pipeline usa artefactos y su propio resumen.
