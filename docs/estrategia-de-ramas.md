# Estrategia de ramas: GitHub Flow

Una sola rama permanente, `main`, siempre desplegable. Todo cambio entra por pull request.

```
main ──●────────●────────●──────────●──▶   (tags v0.1.0, v0.2.0… = entrega de sprint)
        \      /  \     /    \     /
         HU-12      fix-31     HU-15
```

## Reglas
| Regla | Detalle |
|---|---|
| `main` protegida | Nadie hace push directo. Solo entra por PR aprobado y con el check de Jenkins en verde. |
| Ramas cortas | Una rama por historia de usuario o corrección, viva pocos días: `HU-<n>-descripcion` o `fix-<n>-descripcion` (n = número del ítem en GitHub Projects). |
| PR hacia `main` | Jenkins ejecuta pruebas, cobertura, SonarQube y los escáneres de seguridad. Si el gate bloquea, no se fusiona. |
| Revisión | Al menos 1 aprobación. Cambios en `.devsecops/` o en el `Jenkinsfile` requieren al rol de Ciberseguridad o DevSecOps. |
| Entrega de sprint | Tag sobre `main`: `v0.<sprint>.0` (correcciones dentro del sprint: `v0.<sprint>.1`). |
| Liberación | Después de fusionar, el build de `main` construye la imagen, la prueba con ZAP y espera la aprobación de liberación. |

## Por qué no GitFlow
SonarQube Cloud (plan gratuito) solo analiza la rama `main` y los PR que apuntan a `main`. Con una rama `develop`, la mayoría de cambios quedaría sin análisis de calidad. GitHub Flow, además, es más simple para equipos de 9 integrantes y sprints cortos.

## Flujo diario
```bash
git switch main && git pull
git switch -c HU-12-registro-alumno
# ... commits pequeños ...
git push -u origin HU-12-registro-alumno
# abrir el PR hacia main, esperar el check de Jenkins y la revisión, fusionar y borrar la rama
```
