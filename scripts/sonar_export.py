#!/usr/bin/env python3
"""
sonar_export.py — Exporta el resultado de un análisis de SonarQube (Cloud o Server)
a sonar.json, para que normalize_gate.py lo incluya en el gate y en el reporte.

Pasos:
  1. Lee report-task.txt (lo deja el scanner en target/sonar/ o .scannerwork/).
  2. Espera a que el servidor termine de procesar el análisis (api/ce/task).
  3. Descarga: estado del quality gate, cobertura, problemas de SEGURIDAD
     y security hotspots pendientes de revisión.

El token se lee de la variable de entorno SONAR_TOKEN. Solo usa la biblioteca estándar.
Código de salida: 0 = exportado, 2 = error (el pipeline decide si eso bloquea).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


def leer_report_task(ruta: Path) -> dict:
    datos = {}
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        if "=" in linea:
            k, v = linea.split("=", 1)
            datos[k.strip()] = v.strip()
    return datos


class Sonar:
    def __init__(self, url: str, token: str | None):
        self.url = url.rstrip("/")
        self.cabeceras = {"Accept": "application/json"}
        if token:
            self.cabeceras["Authorization"] = "Basic " + base64.b64encode(f"{token}:".encode()).decode()

    def get(self, ruta: str, **params) -> dict:
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "")})
        req = urllib.request.Request(f"{self.url}/{ruta}?{q}", headers=self.cabeceras)
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8"))

    def paginado(self, ruta: str, clave: str, **params) -> list:
        res, p = [], 1
        while True:
            d = self.get(ruta, p=p, ps=500, **params)
            res += d.get(clave, [])
            total = (d.get("paging") or {}).get("total", d.get("total", 0))
            if len(res) >= total or not d.get(clave) or p >= 20:
                return res
            p += 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report-task", required=True, help="Ruta de report-task.txt")
    ap.add_argument("--out", default="sonar.json")
    ap.add_argument("--pull-request", default="", help="Número de PR analizado (vacío = rama)")
    ap.add_argument("--branch", default="", help="Rama analizada (si no es PR)")
    ap.add_argument("--timeout", type=int, default=300, help="Segundos máximos de espera del procesamiento")
    a = ap.parse_args()

    ruta = Path(a.report_task)
    if not ruta.is_file():
        print(f"No existe {ruta}: el análisis de Sonar no se ejecutó", file=sys.stderr)
        return 2
    rt = leer_report_task(ruta)
    s = Sonar(rt.get("serverUrl", "https://sonarcloud.io"), os.environ.get("SONAR_TOKEN"))
    proyecto = rt.get("projectKey")
    org = rt.get("organization") or os.environ.get("SONAR_ORG") or None

    # 1) Esperar el procesamiento en el servidor
    limite = time.time() + a.timeout
    tarea = {}
    while time.time() < limite:
        tarea = s.get("api/ce/task", id=rt["ceTaskId"]).get("task", {})
        if tarea.get("status") in ("SUCCESS", "FAILED", "CANCELED"):
            break
        time.sleep(5)
    if tarea.get("status") != "SUCCESS":
        print(f"El análisis de Sonar no terminó bien: {tarea.get('status') or 'tiempo agotado'}", file=sys.stderr)
        return 2

    alcance = {"pullRequest": a.pull_request} if a.pull_request else {"branch": a.branch}

    # 2) Quality gate del análisis
    qg = s.get("api/qualitygates/project_status", analysisId=tarea["analysisId"]).get("projectStatus", {})

    # 3) Cobertura (global y en código nuevo)
    medidas = {}
    try:
        comp = s.get("api/measures/component", component=proyecto,
                     metricKeys="coverage,new_coverage,line_coverage,tests", **alcance).get("component", {})
        for m in comp.get("measures", []):
            v = m.get("value") or ((m.get("period") or {}).get("value"))
            medidas[m["metric"]] = float(v) if v not in (None, "") else None
    except Exception as e:  # la cobertura es informativa: nuestro gate usa jacoco.xml
        print(f"Aviso: no se pudo leer la cobertura de Sonar: {e}", file=sys.stderr)

    # 4) Problemas de seguridad abiertos y hotspots por revisar
    problemas = s.paginado("api/issues/search", "issues", componentKeys=proyecto, organization=org,
                           impactSoftwareQualities="SECURITY", resolved="false", **alcance)
    hotspots = s.paginado("api/hotspots/search", "hotspots", projectKey=proyecto,
                          status="TO_REVIEW", **alcance)

    panel = f"{s.url}/dashboard?id={urllib.parse.quote(proyecto or '')}"
    if a.pull_request:
        panel += f"&pullRequest={a.pull_request}"
    salida = {
        "servidor": s.url,
        "proyecto": proyecto,
        "organizacion": org,
        "pull_request": a.pull_request or None,
        "rama": None if a.pull_request else (a.branch or None),
        "panel": panel,
        "quality_gate": {"estado": qg.get("status"),
                         "condiciones": [{k: c.get(k) for k in ("metricKey", "status", "actualValue",
                                                                  "errorThreshold", "comparator")}
                                         for c in qg.get("conditions", [])]},
        "medidas": medidas,
        "issues": problemas,
        "hotspots": hotspots,
    }
    Path(a.out).write_text(json.dumps(salida, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Sonar: quality gate {qg.get('status')} · cobertura {medidas.get('coverage')} % · "
          f"{len(problemas)} problema(s) de seguridad · {len(hotspots)} hotspot(s) por revisar · {panel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
