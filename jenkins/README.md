# Jenkins local (prototipo)

Orquestador alternativo a GitHub Actions, pedido por el docente. Usa **las mismas herramientas, el mismo `normalize_gate.py` y el mismo contrato de datos**. Corre en Docker en una PC (prototipo) y, más adelante, en la máquina de la universidad encendida 24/7. Costo: **USD 0**.

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
