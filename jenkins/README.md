# Jenkins local (prototipo)

Orquestador alternativo a GitHub Actions, pedido por el docente. Usa **el mismo `normalize_gate.py` y el mismo contrato de datos** que Actions; desde la fase 2 agrega pruebas, cobertura y SonarQube Cloud. Corre en Docker en una PC (prototipo) y, más adelante, en la máquina de la universidad encendida 24/7. Costo: **USD 0**.

```
GitHub ◄──(cada 5 min: ¿commits o PR nuevos?)── Jenkins (Docker, esta PC)
   ▲                                              │ escaneos · gate · imagen · staging local · ZAP · reporte
   └────────── estado ✅/❌ en el commit o PR ◄────┘
```

- No necesita IP pública ni webhooks: Jenkins consulta GitHub cada 5 minutos.
- El staging es **local**: la aplicación se levanta en un contenedor, ZAP la ataca y luego se elimina.
- Todo está definido como código (`docker-compose.yml`, `plugins.txt`, `casc.yaml` y la librería en `library/`). Mudarlo a otra máquina = clonar, crear `.env` y `docker compose up -d --build`.

## Requisitos
- Docker Desktop con WSL2, en ejecución.
- Unos 30 GB libres (imágenes y caché).
- Un token de GitHub. Opción simple: *Settings → Developer settings → Personal access tokens (classic)*, con los scopes `public_repo` y `repo:status`.

## Instalación (PowerShell)
```powershell
cd D:\devsecops-templates
git fetch
git checkout jenkins/prototipo
cd jenkins
copy .env.example .env
notepad .env          # contraseña de admin, usuario y token de GitHub
docker compose up -d --build
docker compose logs -f jenkins     # esperar "Jenkins is fully up and running" (Ctrl+C para salir)
```
Abrir **http://localhost:8080** y entrar con el usuario y la contraseña del `.env`. El job **g00-prueba** aparece creado. Jenkins lo escanea solo; para no esperar, use *Scan Repository Now*.

## Uso diario
| Acción | Comando |
|---|---|
| Detener Jenkins | `docker compose stop` |
| Iniciar Jenkins | `docker compose start` |
| Aplicar cambios de configuración | `docker compose up -d --build` |
| Ver logs | `docker compose logs -f jenkins` |

La configuración (`casc.yaml`) se reaplica en cada inicio, así que los cambios hechos a mano en la interfaz se pierden. Los cambios se hacen en el repositorio.

## Agregar un repositorio de grupo
1. En el repo del grupo, crear un `Jenkinsfile`:
   ```groovy
   @Library('devsecops') _
   devsecopsPipeline(grupo: 'g01')
   ```
2. En `casc.yaml`, copiar el bloque `multibranchPipelineJob('g00-prueba')` y cambiar el nombre del repositorio.
3. Ejecutar `docker compose up -d --build`.

## Calidad: pruebas, cobertura y SonarQube Cloud (fase 2)
El build ejecuta las pruebas (`mvn verify`) con JaCoCo. No hace falta tocar el `pom.xml` del grupo: el pipeline invoca JaCoCo desde la línea de comandos.

- **Pruebas:** si una prueba falla, el build falla. Los resultados se ven en la página del build (*Test Result*).
- **Cobertura:** el gate exige `coberturaMinima` (por defecto 60 % de líneas). La define el **QA líder** en el `Jenkinsfile` del grupo. El reporte navegable queda en `devsecops-reporte/cobertura/index.html`.
- **SonarQube Cloud:** reemplaza a Semgrep y SpotBugs como SAST y aporta métricas de calidad. Sus problemas de seguridad entran al mismo gate (HIGH o superior bloquea). Los *security hotspots* aparecen como hallazgos por revisar y no bloquean. El quality gate de Sonar es informativo, salvo `sonarGate: 'bloquear'`.
- El plan gratuito de SonarQube Cloud analiza **solo `main` y los PR hacia `main`** (por eso la estrategia de ramas es GitHub Flow, ver `docs/estrategia-de-ramas.md`). En otras ramas el paso de Sonar se omite.

```groovy
@Library('devsecops') _
devsecopsPipeline(grupo: 'g01', coberturaMinima: 60)   // sonarGate: 'bloquear' para exigir el quality gate de Sonar
```

### Configurar SonarQube Cloud (una vez por organización)
1. Entrar a https://sonarcloud.io con la cuenta de GitHub → *Create organization* → importar la organización `Taller-de-proyectos-2027-I` (plan **Free**, repos públicos).
2. Importar cada repositorio de grupo (*Analyze new project*). Sonar asigna la clave `<organización de GitHub>_<repo>` (por ejemplo `Taller-de-proyectos-2027-I_g00-prueba`), que es la que usa el pipeline; si fuera otra, se indica con `sonarProjectKey`.
3. En cada proyecto: *Administration → Analysis Method* → **desactivar Automatic Analysis** (el análisis lo hace Jenkins).
4. *My Account → Security* → generar un token.
5. En el `.env` de Jenkins: `SONAR_ORG=<clave de la organización en Sonar>` (la parte de la URL después de `/organizations/`) y `SONAR_TOKEN=<token>`. Luego `docker compose up -d --build`.

Sin `SONAR_ORG`, el pipeline sigue funcionando con Semgrep y SpotBugs.

## Seguridad: diferencias entre el prototipo y la máquina de la universidad
| Prototipo (esta PC) | Máquina de la universidad |
|---|---|
| Jenkins corre como `root` y usa el Docker del host (control total de Docker) | Agente separado y usuario sin privilegios |
| Ejecutores en el propio controlador | Controlador con 0 ejecutores y builds en el agente |
| Puerto solo en `127.0.0.1` | Acceso por la red de la universidad, con HTTPS y usuarios por rol |
| Usuario `admin` local | Usuarios por integrante; aprobadores = equipo DevSecOps |

## Problemas frecuentes
- **`permission denied ... docker.sock`:** Docker Desktop no está iniciado o falta `user: root` en el compose.
- **Error de configuración al iniciar:** revisar `docker compose logs jenkins`; casi siempre es un valor vacío en `.env`.
- **El job no ve ramas:** el token no tiene permisos o `GITHUB_ORG` está mal escrito.
- **Falla la descarga de plugins al construir:** problema de red; repetir `docker compose build`.
