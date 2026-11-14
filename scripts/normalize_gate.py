#!/usr/bin/env python3
"""
normalize_gate.py — Normaliza los reportes de seguridad del pipeline DevSecOps
al contrato de datos común (schema/hallazgo.schema.json), aplica supresiones
justificadas, evalúa el gate de seguridad y calcula métricas de la ejecución.

Entradas soportadas (detectadas por nombre de archivo dentro de --reports):
  gitleaks.sarif      -> categoria=secretos,   etapa=integracion
  spotbugs.sarif      -> categoria=sast,       etapa=integracion
  semgrep.sarif       -> categoria=sast,       etapa=integracion
  trivy-fs.sarif      -> categoria=sca,        etapa=integracion
  checkov.sarif       -> categoria=iac,        etapa=integracion
  checkov-dockerfile.sarif -> categoria=iac,   etapa=integracion
  trivy-image.sarif   -> categoria=contenedor, etapa=build
  zap-baseline.json   -> categoria=dast,       etapa=pruebas
  zap-api.json        -> categoria=dast,       etapa=pruebas
  sonar.json          -> categoria=sast,       etapa=integracion  (scripts/sonar_export.py)
  jacoco*.xml         -> cobertura de pruebas (no son hallazgos; los evalúa --min-coverage)

Solo usa la biblioteca estándar; PyYAML es opcional (para suppressions.yml).
Código de salida: 0 = gate aprobado, 1 = gate bloqueado (si --enforce), 2 = error.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCHEMA_VERSION = "1.0"

SEVERIDADES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RANGO = {s: i for i, s in enumerate(SEVERIDADES)}

# archivo -> (herramienta, categoria, etapa, severidad_por_defecto)
FUENTES = {
    "gitleaks.sarif": ("gitleaks", "secretos", "integracion", "CRITICAL"),
    "spotbugs.sarif": ("spotbugs-findsecbugs", "sast", "integracion", None),
    "semgrep.sarif": ("semgrep", "sast", "integracion", None),
    "trivy-fs.sarif": ("trivy-fs", "sca", "integracion", None),
    "checkov.sarif": ("checkov", "iac", "integracion", None),
    "checkov-dockerfile.sarif": ("checkov", "iac", "integracion", None),
    "trivy-image.sarif": ("trivy-image", "contenedor", "build", None),
    "zap-baseline.json": ("zap-baseline", "dast", "pruebas", None),
    "zap-api.json": ("zap-api", "dast", "pruebas", None),
    "sonar.json": ("sonarqube", "sast", "integracion", None),
}

ETAPAS_POR_ALCANCE = {
    "ci": {"integracion"},
    "image": {"build"},
    "dast": {"pruebas"},
    "all": {"integracion", "build", "pruebas"},
}

NIVEL_SARIF = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,}|GHSA-[\w-]+)", re.IGNORECASE)


def ahora_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def huella(*partes: str) -> str:
    return hashlib.sha256("|".join(p or "" for p in partes).encode()).hexdigest()[:16]


def severidad_por_cvss(valor) -> str | None:
    try:
        v = float(valor)
    except (TypeError, ValueError):
        return None
    if v >= 9.0:
        return "CRITICAL"
    if v >= 7.0:
        return "HIGH"
    if v >= 4.0:
        return "MEDIUM"
    if v > 0:
        return "LOW"
    return "INFO"


def ruta_relativa(uri):
    """Normaliza la ruta de un hallazgo a relativa al repositorio.

    Cada orquestador ejecuta los escáneres en rutas distintas (GitHub Actions:
    relativas; Jenkins: /var/jenkins_home/workspace/<job>/...). Sin esto, las
    supresiones y las huellas (id) no coinciden entre orquestadores.
    """
    if not uri:
        return uri
    ruta = uri[7:] if uri.startswith("file://") else uri
    base = os.getcwd().rstrip("/") + "/"
    # Algunas herramientas (Checkov) omiten la "/" inicial de la ruta absoluta
    for prefijo in (base, base.lstrip("/")):
        if prefijo and ruta.startswith(prefijo):
            ruta = ruta[len(prefijo):]
            break
    return ruta[2:] if ruta.startswith("./") else ruta


# --------------------------------------------------------------------------- #
# Lectores
# --------------------------------------------------------------------------- #
def leer_sarif(ruta: Path, herramienta: str, categoria: str, etapa: str, sev_def: str | None):
    data = json.loads(ruta.read_text(encoding="utf-8") or "{}")
    hallazgos = []
    for run in data.get("runs", []) or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        reglas = {}
        for idx, r in enumerate(driver.get("rules", []) or []):
            reglas[r.get("id")] = r
            reglas[idx] = r
        for res in run.get("results", []) or []:
            if res.get("kind") in ("pass", "notApplicable"):
                continue
            supr_nativa = None
            if res.get("suppressions"):
                # Supresión nativa de la herramienta (nosemgrep, checkov:skip, .trivyignore...)
                supr_nativa = {"origen": "herramienta",
                               "justificacion": (res["suppressions"][0] or {}).get("justification")}
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or "desconocida"
            regla = reglas.get(rid) or reglas.get(res.get("ruleIndex"), {}) or {}
            props_r = regla.get("properties") or {}
            props_res = res.get("properties") or {}
            etiquetas = [str(t) for t in (props_r.get("tags") or [])]

            # --- severidad ---------------------------------------------------
            sev = None
            for t in etiquetas:  # Trivy coloca la severidad como etiqueta
                if t.upper() in RANGO and t.upper() != "INFO":
                    sev = t.upper()
                    break
            if not sev:
                sev = severidad_por_cvss(props_res.get("security-severity")) or \
                      severidad_por_cvss(props_r.get("security-severity"))
            if not sev and sev_def:
                sev = sev_def
            if not sev:
                nivel = res.get("level") or \
                        ((regla.get("defaultConfiguration") or {}).get("level")) or "warning"
                sev = NIVEL_SARIF.get(nivel, "MEDIUM")

            # --- CWE / CVE ---------------------------------------------------
            texto = " ".join([
                rid,
                " ".join(etiquetas),
                json.dumps(regla.get("relationships") or []),
                (regla.get("shortDescription") or {}).get("text", ""),
                (regla.get("fullDescription") or {}).get("text", ""),
            ])
            cwes = sorted({f"CWE-{n}" for n in CWE_RE.findall(texto)})
            for rel in regla.get("relationships") or []:
                tgt = rel.get("target") or {}
                comp = ((tgt.get("toolComponent") or {}).get("name") or "").upper()
                if comp == "CWE" and str(tgt.get("id", "")).isdigit():
                    cwes = sorted(set(cwes) | {f"CWE-{tgt['id']}"})
            cve_m = CVE_RE.search(rid) or CVE_RE.search(texto)
            cve = cve_m.group(1).upper() if cve_m else None

            # --- ubicación -----------------------------------------------------
            archivo, linea = None, None
            locs = res.get("locations") or []
            if locs:
                pl = locs[0].get("physicalLocation") or {}
                archivo = ruta_relativa((pl.get("artifactLocation") or {}).get("uri"))
                linea = (pl.get("region") or {}).get("startLine")

            titulo = ((res.get("message") or {}).get("text")
                      or (regla.get("shortDescription") or {}).get("text") or rid)
            if herramienta.startswith("trivy"):
                # Trivy: "Package: X\nInstalled Version: Y\n...\nFixed Version: Z" -> una línea útil
                campos = dict(l.split(":", 1) for l in titulo.splitlines() if ":" in l)
                campos = {k.strip(): v.strip() for k, v in campos.items()}
                if campos.get("Package"):
                    titulo = (f"{campos['Package']} {campos.get('Installed Version', '')}".strip()
                              + f" → corregido en: {campos.get('Fixed Version') or 'sin versión corregida'}")
            titulo = titulo.strip().splitlines()[0][:240]

            # Huella estable: en Trivy varios paquetes comparten CVE y ubicación (pom.xml),
            # por eso se incluye el paquete (primera línea del mensaje).
            extra = titulo if herramienta.startswith("trivy") else ""
            fp = huella(herramienta, rid, archivo or "", str(linea or ""), extra)

            hallazgos.append({
                "id": fp,
                "herramienta": herramienta,
                "categoria": categoria,
                "etapa": etapa,
                "regla": rid,
                "titulo": titulo,
                "severidad": sev,
                "cwe": cwes,
                "cve": cve,
                "ubicacion": {"archivo": archivo, "linea": linea, "url": None},
                "estado": "suprimido" if supr_nativa else "abierto",
                "supresion": supr_nativa,
            })
    return hallazgos


ZAP_RIESGO = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}


def leer_zap(ruta: Path, herramienta: str, categoria: str, etapa: str, _sev):
    data = json.loads(ruta.read_text(encoding="utf-8") or "{}")
    hallazgos = []
    for sitio in data.get("site", []) or []:
        base = sitio.get("@name", "")
        for a in sitio.get("alerts", []) or []:
            inst = a.get("instances") or [{}]
            url = inst[0].get("uri") or base
            cwe = str(a.get("cweid") or "")
            regla = str(a.get("alertRef") or a.get("pluginid") or "zap")
            hallazgos.append({
                "id": huella(herramienta, regla, base),
                "herramienta": herramienta,
                "categoria": categoria,
                "etapa": etapa,
                "regla": regla,
                "titulo": (a.get("alert") or a.get("name") or regla)[:240],
                "severidad": ZAP_RIESGO.get(str(a.get("riskcode")), "MEDIUM"),
                "cwe": [f"CWE-{cwe}"] if cwe.isdigit() and cwe != "0" and cwe != "-1" else [],
                "cve": None,
                "ubicacion": {"archivo": None, "linea": None, "url": url,
                              "instancias": int(a.get("count") or len(inst))},
                "estado": "abierto",
                "supresion": None,
            })
    return hallazgos


# Severidad de impacto en SonarQube (modo MQR) y severidad clásica (modo estándar)
SONAR_IMPACTO = {"BLOCKER": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO"}
SONAR_CLASICA = {"BLOCKER": "CRITICAL", "CRITICAL": "HIGH", "MAJOR": "MEDIUM", "MINOR": "LOW", "INFO": "INFO"}
# Un hotspot no es una vulnerabilidad confirmada: requiere revisión, así que no bloquea con umbral HIGH
SONAR_HOTSPOT = {"HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}


def leer_sonar(ruta: Path, herramienta: str, categoria: str, etapa: str, _sev):
    data = json.loads(ruta.read_text(encoding="utf-8") or "{}")
    proyecto = data.get("proyecto") or ""
    panel = data.get("panel")

    def archivo_de(componente):
        comp = componente or ""
        return comp[len(proyecto) + 1:] if proyecto and comp.startswith(proyecto + ":") else (comp or None)

    hallazgos = []
    for i in data.get("issues", []) or []:
        sev_imp = [x.get("severity") for x in i.get("impacts") or [] if x.get("softwareQuality") == "SECURITY"]
        sev = SONAR_IMPACTO.get(sev_imp[0]) if sev_imp else SONAR_CLASICA.get(i.get("severity"), "MEDIUM")
        hallazgos.append({
            "id": huella(herramienta, i.get("key") or ""),
            "herramienta": herramienta, "categoria": categoria, "etapa": etapa,
            "regla": i.get("rule") or "sonar",
            "titulo": (i.get("message") or i.get("rule") or "")[:240],
            "severidad": sev or "MEDIUM",
            "cwe": [], "cve": None,
            "ubicacion": {"archivo": archivo_de(i.get("component")), "linea": i.get("line"), "url": None},
            "estado": "abierto", "supresion": None,
        })
    for hs in data.get("hotspots", []) or []:
        hallazgos.append({
            "id": huella(herramienta + "-hotspot", hs.get("key") or ""),
            "herramienta": herramienta + "-hotspot", "categoria": categoria, "etapa": etapa,
            "regla": hs.get("ruleKey") or hs.get("securityCategory") or "hotspot",
            "titulo": ("Revisar (hotspot): " + (hs.get("message") or ""))[:240],
            "severidad": SONAR_HOTSPOT.get(hs.get("vulnerabilityProbability"), "LOW"),
            "cwe": [], "cve": None,
            "ubicacion": {"archivo": archivo_de(hs.get("component")), "linea": hs.get("line"), "url": None},
            "estado": "abierto", "supresion": None,
        })
    return hallazgos


def leer_sonar_resumen(reports: str):
    for ruta in Path(reports).rglob("sonar.json"):
        try:
            d = json.loads(ruta.read_text(encoding="utf-8") or "{}")
        except (json.JSONDecodeError, OSError):
            return None
        return {"quality_gate": (d.get("quality_gate") or {}).get("estado"),
                "condiciones": (d.get("quality_gate") or {}).get("condiciones", []),
                "cobertura": (d.get("medidas") or {}).get("coverage"),
                "cobertura_codigo_nuevo": (d.get("medidas") or {}).get("new_coverage"),
                "panel": d.get("panel")}
    return None


def leer_cobertura(reports: str):
    """Cobertura de líneas a partir de los jacoco*.xml (suma de todos los módulos)."""
    import xml.etree.ElementTree as ET
    cubiertas = perdidas = 0
    archivos = sorted(Path(reports).rglob("jacoco*.xml"))
    for ruta in archivos:
        try:
            raiz = ET.parse(ruta).getroot()
        except (ET.ParseError, OSError):
            continue
        for c in raiz.findall("counter"):
            if c.get("type") == "LINE":
                cubiertas += int(c.get("covered", 0))
                perdidas += int(c.get("missed", 0))
    total = cubiertas + perdidas
    if not archivos:
        return None
    return {"lineas_cubiertas": cubiertas, "lineas_totales": total,
            "porcentaje": round(100 * cubiertas / total, 1) if total else 0.0,
            "archivos": [r.name for r in archivos]}


# --------------------------------------------------------------------------- #
# Supresiones justificadas (.devsecops/suppressions.yml)
# --------------------------------------------------------------------------- #
def cargar_supresiones(ruta: str | None):
    if not ruta or not Path(ruta).is_file():
        return []
    texto = Path(ruta).read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        datos = yaml.safe_load(texto) or []
    except ImportError:
        datos = json.loads(texto) if texto.strip().startswith("[") else []
        if not datos:
            print("::warning::PyYAML no disponible; se ignoran las supresiones", file=sys.stderr)
    if isinstance(datos, dict):
        datos = datos.get("supresiones", [])
    return [d for d in datos if isinstance(d, dict)]


def aplicar_supresiones(hallazgos, supresiones, hoy: dt.date):
    avisos = []
    for s in supresiones:
        faltan = [c for c in ("justificacion", "aprobado_por") if not s.get(c)]
        if faltan:
            avisos.append(f"Supresión {s} ignorada: faltan {', '.join(faltan)}")
            continue
        expira = s.get("expira")
        if expira:
            try:
                f_exp = expira if isinstance(expira, dt.date) else dt.date.fromisoformat(str(expira))
            except ValueError:
                avisos.append(f"Supresión con fecha inválida ignorada: {s}")
                continue
            if f_exp < hoy:
                avisos.append(f"Supresión vencida ({f_exp}) ignorada: {s.get('id') or s.get('regla')}")
                continue
        for h in hallazgos:
            if h["estado"] != "abierto":
                continue
            coincide = False
            if s.get("id"):
                coincide = s["id"] == h["id"]
            elif s.get("regla"):
                coincide = (s["regla"] == h["regla"]
                            and (not s.get("herramienta") or s["herramienta"] == h["herramienta"])
                            and (not s.get("archivo") or s["archivo"] == (h["ubicacion"] or {}).get("archivo")))
            if coincide:
                h["estado"] = "suprimido"
                h["supresion"] = {
                    "origen": "suppressions.yml",
                    "justificacion": s["justificacion"],
                    "aprobado_por": s["aprobado_por"],
                    "expira": str(expira) if expira else None,
                }
    return avisos


# --------------------------------------------------------------------------- #
# Métricas
# --------------------------------------------------------------------------- #
def contar_kloc(app_dir: str) -> float:
    lineas = 0
    for p in Path(app_dir).rglob("*.java"):
        partes = set(p.parts)
        if partes & {"test", "target", "build", ".git", "node_modules"}:
            continue
        try:
            lineas += sum(1 for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip())
        except OSError:
            pass
    return round(lineas / 1000.0, 3)


def fecha_commit(sha: str | None) -> str | None:
    try:
        cmd = ["git", "log", "-1", "--format=%cI"] + ([sha] if sha else [])
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip() or None
    except Exception:
        return None


def overhead_desde_jobs(ruta: str | None):
    """Calcula el overhead de seguridad a partir del JSON de la API de jobs de GitHub."""
    if not ruta or not Path(ruta).is_file():
        return None
    try:
        jobs = json.loads(Path(ruta).read_text()).get("jobs", [])
    except json.JSONDecodeError:
        return None

    def dur(j):
        try:
            ini = dt.datetime.fromisoformat(j["started_at"].replace("Z", "+00:00"))
            fin = dt.datetime.fromisoformat((j.get("completed_at") or j["started_at"]).replace("Z", "+00:00"))
            return max((fin - ini).total_seconds(), 0)
        except (KeyError, TypeError, ValueError):
            return 0

    detalle, total, seg = [], 0.0, 0.0
    for j in jobs:
        if not j.get("completed_at"):
            continue  # el propio job de reporte aún está corriendo
        d = dur(j)
        es_seg = "SEC ·" in (j.get("name") or "")
        total += d
        seg += d if es_seg else 0
        detalle.append({"job": j.get("name"), "segundos": round(d), "seguridad": es_seg,
                        "resultado": j.get("conclusion")})
    return {
        "segundos_totales": round(total),
        "segundos_seguridad": round(seg),
        "porcentaje_overhead": round(100 * seg / total, 1) if total else None,
        "jobs": detalle,
    }


# --------------------------------------------------------------------------- #
# Resumen legible (GITHUB_STEP_SUMMARY)
# --------------------------------------------------------------------------- #
def resumen_md(hallazgos, umbral, bloqueantes, metricas, avisos, alcance, salida=None) -> str:
    def conteo(filtro):
        c = {s: 0 for s in reversed(SEVERIDADES)}
        for h in hallazgos:
            if filtro(h):
                c[h["severidad"]] += 1
        return c

    cats = sorted({h["categoria"] for h in hallazgos})
    motivos = ((salida or {}).get("gate") or {}).get("motivos") or []
    estado = "❌ BLOQUEADO" if (bloqueantes or motivos) else "✅ APROBADO"
    md = [f"## Gate de seguridad ({alcance}) — {estado}",
          f"Umbral: bloquea severidad **{umbral}** o superior · "
          f"Hallazgos abiertos: **{sum(1 for h in hallazgos if h['estado']=='abierto')}** · "
          f"Bloqueantes: **{len(bloqueantes)}** · "
          f"Suprimidos: **{sum(1 for h in hallazgos if h['estado']=='suprimido')}**", ""]
    if hallazgos:
        md += ["| Categoría | CRITICAL | HIGH | MEDIUM | LOW | INFO |", "|---|---|---|---|---|---|"]
        for c in cats:
            n = conteo(lambda h, c=c: h["categoria"] == c and h["estado"] == "abierto")
            md.append(f"| {c} | " + " | ".join(str(n[s]) for s in reversed(SEVERIDADES)) + " |")
        md.append("")
    cal = (salida or {}).get("calidad")
    if cal:
        cob, son = cal.get("cobertura"), cal.get("sonar")
        md += ["### Calidad (QA)"]
        md.append(f"- Cobertura de líneas (JaCoCo): **{cob['porcentaje']:g} %** "
                  f"({cob['lineas_cubiertas']}/{cob['lineas_totales']})" if cob else "- Cobertura de líneas: sin reporte")
        if cal.get("cobertura_minima"):
            md.append(f"- Mínimo exigido: {cal['cobertura_minima']:g} %")
        if son:
            md.append(f"- SonarQube: quality gate **{son.get('quality_gate')}** ({cal.get('sonar_gate')}) · "
                      f"cobertura código nuevo {son.get('cobertura_codigo_nuevo')} % · {son.get('panel')}")
        for m in motivos:
            md.append(f"- ❌ {m}")
        md.append("")
    if bloqueantes:
        md += ["### Hallazgos que bloquean", "| Sev. | Herramienta | Regla | Ubicación | id |", "|---|---|---|---|---|"]
        for h in sorted(bloqueantes, key=lambda x: -RANGO[x["severidad"]])[:25]:
            u = h["ubicacion"] or {}
            loc = u.get("url") or f"{u.get('archivo') or '-'}:{u.get('linea') or ''}"
            md.append(f"| {h['severidad']} | {h['herramienta']} | `{h['regla']}` | `{loc}` | `{h['id']}` |")
        if len(bloqueantes) > 25:
            md.append(f"\n… y {len(bloqueantes) - 25} más (ver artefacto `devsecops-hallazgos`).")
        md.append("\nPara aceptar un riesgo, agregue una entrada justificada en `.devsecops/suppressions.yml` "
                  "(requiere aprobación del rol de Ciberseguridad).")
    if metricas:
        md += ["", "### Métricas de la ejecución"]
        if metricas.get("kloc") is not None:
            md.append(f"- KLOC analizadas: {metricas['kloc']} · densidad (abiertos/KLOC): "
                      f"{metricas.get('densidad_vulnerabilidades')}")
        if metricas.get("tiempo_deteccion_min") is not None:
            md.append(f"- Tiempo commit → detección: {metricas['tiempo_deteccion_min']} min")
        ov = metricas.get("overhead")
        if ov and ov.get("porcentaje_overhead") is not None:
            md.append(f"- Overhead de seguridad: {ov['porcentaje_overhead']} % "
                      f"({ov['segundos_seguridad']} s de {ov['segundos_totales']} s)")
    if avisos:
        md += ["", "### Avisos"] + [f"- {a}" for a in avisos]
    return "\n".join(md) + "\n"


# --------------------------------------------------------------------------- #
# Reporte HTML legible (Jenkins y Actions). Usa atributos HTML además de CSS para
# verse bien incluso donde la política de seguridad bloquea estilos (Jenkins).
# --------------------------------------------------------------------------- #
COLOR_SEV = {"CRITICAL": ("#7B0000", "#FFFFFF"), "HIGH": ("#C00000", "#FFFFFF"),
             "MEDIUM": ("#F4B183", "#000000"), "LOW": ("#FFF2CC", "#000000"), "INFO": ("#E7E6E6", "#000000")}
NOMBRE_ALCANCE = {"ci": "Integración", "image": "Imagen", "dast": "DAST", "all": "Global"}


def reporte_html(salida, metricas, avisos) -> str:
    from html import escape as e

    def celda_sev(sev):
        bg, fg = COLOR_SEV.get(sev, ("#FFFFFF", "#000000"))
        return f'<td bgcolor="{bg}" style="background:{bg};color:{fg}"><font color="{fg}"><b>{e(sev)}</b></font></td>'

    def ubic(h):
        u = h.get("ubicacion") or {}
        if u.get("url"):
            return e(u["url"])
        return e(f"{u.get('archivo') or '-'}" + (f":{u['linea']}" if u.get("linea") else ""))

    hs = salida["hallazgos"]
    abiertos = sorted([h for h in hs if h["estado"] == "abierto"], key=lambda x: (-RANGO[x["severidad"]], x["herramienta"]))
    suprimidos = [h for h in hs if h["estado"] == "suprimido"]
    gate = salida["gate"]
    ok = gate["resultado"] == "aprobado"
    alc = NOMBRE_ALCANCE.get(salida.get("alcance"), salida.get("alcance"))
    tabla = 'border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%"'
    out = ['<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">',
           f"<title>Reporte DevSecOps · {e(str(salida.get('repo') or ''))}</title>",
           "<style>body{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#1A1A1A}"
           "th{background:#D9E2F3;text-align:left}td,th{border:1px solid #BFBFBF;vertical-align:top;font-size:13px}"
           "h1{color:#1F3864;font-size:22px}h2{color:#2E75B6;font-size:17px;margin-top:28px}</style></head>",
           '<body><font face="Arial">',
           f"<h1>Reporte DevSecOps · {alc}</h1>",
           f"<p>Repositorio <b>{e(str(salida.get('repo') or '-'))}</b> · grupo <b>{e(str(salida.get('grupo') or '-'))}</b>"
           f" · rama <b>{e(str(salida.get('rama') or '-'))}</b> · commit <code>{e(str(salida.get('commit') or '-')[:12])}</code>"
           f" · {e(str(salida.get('fecha_deteccion') or ''))}</p>"]
    bg = "#E2EFDA" if ok else "#F8CECC"
    out.append(f'<table {tabla}><tr><td bgcolor="{bg}" style="background:{bg};font-size:16px">'
               f"<b>Gate: {'✅ APROBADO' if ok else '❌ BLOQUEADO'}</b> · bloquea severidad <b>{e(gate['umbral'])}</b> o superior · "
               f"abiertos <b>{len(abiertos)}</b> · bloqueantes <b>{gate['bloqueantes']}</b> · suprimidos <b>{len(suprimidos)}</b>"
               "</td></tr></table>")
    for m in gate.get("motivos") or []:
        out.append(f'<p><font color="#C00000"><b>❌ {e(m)}</b></font></p>')

    cal = salida.get("calidad")
    if cal:
        cob, son = cal.get("cobertura"), cal.get("sonar")
        out.append(f"<h2>Calidad (QA)</h2><table {tabla}>")
        out.append("<tr><th>Cobertura de líneas (JaCoCo)</th><td>"
                   + (f"<b>{cob['porcentaje']:g} %</b> ({cob['lineas_cubiertas']} de {cob['lineas_totales']} líneas)"
                      if cob else "sin reporte") + "</td></tr>")
        minimo = f"{cal['cobertura_minima']:g} %" if cal.get("cobertura_minima") else "no se exige"
        out.append(f"<tr><th>Mínimo exigido</th><td>{e(minimo)}</td></tr>")
        if son:
            panel = son.get("panel") or ""
            out.append(f"<tr><th>SonarQube · quality gate</th><td><b>{e(str(son.get('quality_gate')))}</b> "
                       f"({e(cal.get('sonar_gate') or '')}) · <a href=\"{e(panel)}\">ver panel</a></td></tr>")
            out.append(f"<tr><th>SonarQube · cobertura (global / código nuevo)</th><td>{e(str(son.get('cobertura')))} % / "
                       f"{e(str(son.get('cobertura_codigo_nuevo')))} %</td></tr>")
            fallidas = [c for c in son.get("condiciones") or [] if c.get("status") == "ERROR"]
            if fallidas:
                out.append("<tr><th>Condiciones no cumplidas</th><td>" + "<br>".join(
                    e(f"{c.get('metricKey')}: {c.get('actualValue')} (umbral {c.get('comparator')} {c.get('errorThreshold')})")
                    for c in fallidas) + "</td></tr>")
        out.append("</table>")

    cats = sorted({h["categoria"] for h in hs})
    if cats:
        out.append(f"<h2>Resumen por categoría (hallazgos abiertos)</h2><table {tabla}><tr><th>Categoría</th>"
                   + "".join(f"<th>{s}</th>" for s in reversed(SEVERIDADES)) + "</tr>")
        for c in cats:
            fila = "".join(f"<td>{sum(1 for h in abiertos if h['categoria'] == c and h['severidad'] == s)}</td>"
                           for s in reversed(SEVERIDADES))
            out.append(f"<tr><td>{e(c)}</td>{fila}</tr>")
        out.append("</table>")

    out.append(f"<h2>Hallazgos abiertos ({len(abiertos)})</h2>")
    if abiertos:
        out.append(f"<table {tabla}><tr><th>Severidad</th><th>Herramienta</th><th>Hallazgo</th><th>Ubicación</th>"
                   "<th>CWE / CVE</th><th>¿Bloquea?</th><th>id</th></tr>")
        for h in abiertos:
            ref = ", ".join(h.get("cwe") or []) + ((" · " if h.get("cwe") else "") + h["cve"] if h.get("cve") else "")
            out.append(f"<tr>{celda_sev(h['severidad'])}<td>{e(h['herramienta'])}<br><small>{e(h['regla'])}</small></td>"
                       f"<td>{e(h['titulo'])}</td><td><small>{ubic(h)}</small></td><td>{e(ref) or '-'}</td>"
                       f"<td>{'<b>Sí</b>' if h.get('bloquea') else 'No'}</td><td><code>{e(h['id'])}</code></td></tr>")
        out.append("</table>")
    else:
        out.append("<p>Sin hallazgos abiertos.</p>")

    if suprimidos:
        out.append(f"<h2>Riesgos aceptados / suprimidos ({len(suprimidos)})</h2><table {tabla}><tr><th>Severidad</th>"
                   "<th>Herramienta</th><th>Hallazgo</th><th>Ubicación</th><th>Justificación</th><th>Aprobado por</th><th>Vence</th></tr>")
        for h in suprimidos:
            sp = h.get("supresion") or {}
            out.append(f"<tr>{celda_sev(h['severidad'])}<td>{e(h['herramienta'])}<br><small>{e(h['regla'])}</small></td>"
                       f"<td>{e(h['titulo'])}</td><td><small>{ubic(h)}</small></td>"
                       f"<td>{e(str(sp.get('justificacion') or '-'))}</td><td>{e(str(sp.get('aprobado_por') or sp.get('origen') or '-'))}</td>"
                       f"<td>{e(str(sp.get('expira') or '-'))}</td></tr>")
        out.append("</table>")

    out.append(f"<h2>Métricas</h2><table {tabla}>")
    filas = [("KLOC analizadas", metricas.get("kloc")),
             ("Densidad (abiertos / KLOC)", metricas.get("densidad_vulnerabilidades")),
             ("Tiempo commit → detección (min)", metricas.get("tiempo_deteccion_min"))]
    ov = metricas.get("overhead") or {}
    if ov.get("porcentaje_overhead") is not None:
        filas.append(("Overhead de seguridad (%)", ov["porcentaje_overhead"]))
    for k, v in filas:
        out.append(f"<tr><th>{e(k)}</th><td>{e(str(v if v is not None else '-'))}</td></tr>")
    out.append("</table>")
    if avisos:
        out.append("<h2>Avisos</h2><ul>" + "".join(f"<li>{e(a)}</li>" for a in avisos) + "</ul>")
    fuentes = ", ".join(f"{e(f['herramienta'])} · {e(f['archivo'])} ({f['hallazgos']})" for f in salida.get("fuentes", []))
    out.append(f"<p><small>Herramientas analizadas: {fuentes or '-'}. Datos completos en hallazgos.json.</small></p>")
    out.append("</font></body></html>")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Anotaciones de GitHub (se ven en el PR, en la pestaña "Files changed" y en el run)
# --------------------------------------------------------------------------- #
MAX_ANOTACIONES = 8  # GitHub muestra hasta 10 anotaciones de error por paso (+ "y más" + resumen)


def escapar_msg(texto: str) -> str:
    return str(texto).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escapar_prop(texto: str) -> str:
    return escapar_msg(texto).replace(":", "%3A").replace(",", "%2C")


def anotar_dast(hallazgos) -> None:
    """Hallazgos de ZAP que no bloquean: avisos para que Ciberseguridad los revise."""
    dast = [h for h in hallazgos if h["categoria"] == "dast" and h["estado"] == "abierto" and not h.get("bloquea")]
    dast.sort(key=lambda x: -RANGO[x["severidad"]])
    for h in dast[:MAX_ANOTACIONES]:
        u = h.get("ubicacion") or {}
        cwe = ",".join(h.get("cwe") or [])
        print(f"::warning title={escapar_prop(h['severidad'] + ' · ' + h['herramienta'] + ' · ' + h['regla'])}::"
              f"{escapar_msg(h['titulo'] + ' [' + (u.get('url') or '-') + '] ' + cwe + ' instancias=' + str(u.get('instancias', 1)))}")
    if len(dast) > MAX_ANOTACIONES:
        print(f"::warning::… y {len(dast) - MAX_ANOTACIONES} hallazgo(s) DAST más en el artefacto devsecops-reporte")


def anotar_bloqueantes(bloqueantes) -> None:
    orden = sorted(bloqueantes, key=lambda x: -RANGO[x["severidad"]])
    for h in orden[:MAX_ANOTACIONES]:
        u = h.get("ubicacion") or {}
        props = [f"title={escapar_prop(h['severidad'] + ' · ' + h['herramienta'] + ' · ' + h['regla'])}"]
        if u.get("archivo"):
            props.append(f"file={escapar_prop(u['archivo'])}")
            if u.get("linea"):
                props.append(f"line={int(u['linea'])}")
        donde = u.get("url") or u.get("archivo") or "-"
        print(f"::error {','.join(props)}::{escapar_msg(h['titulo'] + ' [' + donde + '] id=' + h['id'])}")
    if len(orden) > MAX_ANOTACIONES:
        print(f"::error::… y {len(orden) - MAX_ANOTACIONES} hallazgo(s) bloqueante(s) más; "
              "ver el resumen del run o el artefacto devsecops-reporte")


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reports", required=True, help="Carpeta con los reportes (se busca recursivamente)")
    ap.add_argument("--scope", choices=ETAPAS_POR_ALCANCE, default="all")
    ap.add_argument("--fail-on", default="HIGH", help="CRITICAL|HIGH|MEDIUM|LOW|NONE")
    ap.add_argument("--suppressions", default=".devsecops/suppressions.yml")
    ap.add_argument("--app-dir", default=".")
    ap.add_argument("--jobs-json", help="Respuesta de la API de jobs de GitHub (para overhead)")
    ap.add_argument("--out", default="hallazgos.json")
    ap.add_argument("--metrics-out", default="metricas.json")
    ap.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"))
    ap.add_argument("--html", help="Ruta del reporte HTML legible (opcional)")
    ap.add_argument("--min-coverage", type=float, default=0.0,
                    help="Cobertura de líneas mínima (%%) según jacoco*.xml; 0 = no se exige")
    ap.add_argument("--sonar-gate", choices=("informar", "bloquear"), default="informar",
                    help="Si el quality gate de Sonar en ERROR bloquea el gate")
    ap.add_argument("--enforce", action="store_true", help="Salir con 1 si el gate bloquea")
    a = ap.parse_args()

    umbral = a.fail_on.upper()
    if umbral not in RANGO and umbral != "NONE":
        print(f"fail-on inválido: {a.fail_on}", file=sys.stderr)
        return 2

    etapas = ETAPAS_POR_ALCANCE[a.scope]
    hallazgos, fuentes_leidas, avisos = [], [], []
    for ruta in sorted(Path(a.reports).rglob("*")):
        meta = FUENTES.get(ruta.name)
        if not meta or not ruta.is_file() or meta[2] not in etapas:
            continue
        lector = leer_sonar if ruta.name == "sonar.json" else (leer_zap if ruta.suffix == ".json" else leer_sarif)
        try:
            nuevos = lector(ruta, *meta)
        except (json.JSONDecodeError, OSError) as e:
            avisos.append(f"No se pudo leer {ruta.name}: {e}")
            continue
        hallazgos += nuevos
        fuentes_leidas.append({"herramienta": meta[0], "archivo": ruta.name, "hallazgos": len(nuevos)})

    # Deduplicar por id (un mismo artefacto puede llegar dos veces)
    vistos, unicos = set(), []
    for h in hallazgos:
        if h["id"] not in vistos:
            vistos.add(h["id"])
            unicos.append(h)
    hallazgos = unicos

    avisos += aplicar_supresiones(hallazgos, cargar_supresiones(a.suppressions), dt.date.today())

    # Contexto de la ejecución (variables estándar de GitHub Actions)
    env = os.environ
    sha = env.get("DEVSECOPS_COMMIT") or env.get("GITHUB_SHA")
    f_commit = fecha_commit(sha)
    f_det = ahora_iso()
    servidor = env.get("GITHUB_SERVER_URL", "https://github.com")
    ctx = {
        "schema_version": SCHEMA_VERSION,
        "repo": env.get("GITHUB_REPOSITORY"),
        "grupo": env.get("DEVSECOPS_GRUPO") or None,
        "sprint": env.get("DEVSECOPS_SPRINT") or None,
        "rama": env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME"),
        "evento": env.get("GITHUB_EVENT_NAME"),
        "commit": sha,
        "fecha_commit": f_commit,
        "fecha_deteccion": f_det,
        "run_id": env.get("GITHUB_RUN_ID"),
        "run_url": (f"{servidor}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
                    if env.get("GITHUB_REPOSITORY") and env.get("GITHUB_RUN_ID") else None),
    }

    bloqueantes = []
    for h in hallazgos:
        h["bloquea"] = (umbral != "NONE" and h["estado"] == "abierto"
                        and RANGO[h["severidad"]] >= RANGO[umbral])
        if h["bloquea"]:
            bloqueantes.append(h)

    # Calidad (QA): cobertura mínima y quality gate de Sonar. Solo en integración y global.
    motivos, calidad = [], None
    if a.scope in ("ci", "all"):
        cobertura = leer_cobertura(a.reports)
        sonar = leer_sonar_resumen(a.reports)
        calidad = {"cobertura": cobertura, "cobertura_minima": a.min_coverage or None,
                   "sonar": sonar, "sonar_gate": a.sonar_gate}
        if a.min_coverage > 0:
            if cobertura is None:
                motivos.append(f"No hay reporte de cobertura (jacoco.xml) y se exige {a.min_coverage:g} %")
            elif cobertura["porcentaje"] < a.min_coverage:
                motivos.append(f"Cobertura {cobertura['porcentaje']:g} % por debajo del mínimo {a.min_coverage:g} %")
        if sonar and sonar.get("quality_gate") == "ERROR":
            if a.sonar_gate == "bloquear":
                motivos.append("Quality gate de SonarQube en ERROR")
            else:
                avisos.append("Quality gate de SonarQube en ERROR (informativo; ver el panel de Sonar)")

    salida = {
        **ctx,
        "alcance": a.scope,
        "gate": {"umbral": umbral, "resultado": "bloqueado" if (bloqueantes or motivos) else "aprobado",
                 "bloqueantes": len(bloqueantes), "motivos": motivos},
        "calidad": calidad,
        "fuentes": fuentes_leidas,
        "hallazgos": [{**{k: ctx[k] for k in ("repo", "grupo", "sprint", "commit", "fecha_commit",
                                               "fecha_deteccion", "run_id")}, **h} for h in hallazgos],
    }
    Path(a.out).write_text(json.dumps(salida, ensure_ascii=False, indent=2), encoding="utf-8")

    # Métricas
    abiertos = [h for h in hallazgos if h["estado"] == "abierto"]
    kloc = contar_kloc(a.app_dir)
    t_det = None
    if f_commit:
        try:
            t_det = round((dt.datetime.fromisoformat(f_det) - dt.datetime.fromisoformat(f_commit))
                          .total_seconds() / 60, 1)
        except ValueError:
            t_det = None
    metricas = {
        **ctx,
        "alcance": a.scope,
        "kloc": kloc,
        "hallazgos_abiertos": len(abiertos),
        "hallazgos_suprimidos": sum(1 for h in hallazgos if h["estado"] == "suprimido"),
        "por_severidad": {s: sum(1 for h in abiertos if h["severidad"] == s) for s in reversed(SEVERIDADES)},
        "por_categoria": {c: sum(1 for h in abiertos if h["categoria"] == c)
                          for c in sorted({h["categoria"] for h in hallazgos})},
        "densidad_vulnerabilidades": round(len(abiertos) / kloc, 3) if kloc else None,
        "tiempo_deteccion_min": t_det,
        "overhead": overhead_desde_jobs(a.jobs_json),
        "cobertura": ((calidad or {}).get("cobertura") or {}).get("porcentaje"),
        "cobertura_minima": (calidad or {}).get("cobertura_minima"),
        "sonar_quality_gate": ((calidad or {}).get("sonar") or {}).get("quality_gate"),
        "gate": salida["gate"],
    }
    Path(a.metrics_out).write_text(json.dumps(metricas, ensure_ascii=False, indent=2), encoding="utf-8")

    md = resumen_md(hallazgos, umbral, bloqueantes, metricas, avisos, a.scope, salida)
    if a.html:
        Path(a.html).write_text(reporte_html(salida, metricas, avisos), encoding="utf-8")
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as f:
            f.write(md)
    print(md)
    for av in avisos:
        print(f"::warning::{escapar_msg(av)}")
    anotar_bloqueantes(bloqueantes)
    if a.scope in ("dast", "all"):
        anotar_dast(hallazgos)
    if bloqueantes:
        print(f"::error::Gate de seguridad bloqueado: {len(bloqueantes)} hallazgo(s) >= {umbral}")
    for m in motivos:
        print(f"::error::Gate de calidad bloqueado: {escapar_msg(m)}")
    return 1 if ((bloqueantes or motivos) and a.enforce) else 0


if __name__ == "__main__":
    sys.exit(main())
