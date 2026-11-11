// =============================================================================
//  Pipeline DevSecOps para Jenkins (Shared Library) — Taller de Proyectos (USMP)
//  Equivalente al workflow reutilizable de GitHub Actions: mismas herramientas,
//  mismo normalize_gate.py y mismo contrato de datos (hallazgos.json, metricas.json).
//
//  Uso en el repositorio del grupo (Jenkinsfile):
//    @Library('devsecops') _
//    devsecopsPipeline(grupo: 'g00')
//
//  Cada herramienta corre en su propio contenedor con --volumes-from jenkins, de modo
//  que ve el workspace en la misma ruta que el controlador.
// =============================================================================
def call(Map cfg = [:]) {
    def c = [
        grupo         : '',
        failOn        : 'HIGH',
        appDir        : '.',
        iacDir        : 'infra',
        dockerfile    : 'Dockerfile',
        semgrepConfigs: 'p/java p/owasp-top-ten',
        deploy        : 'local',          // local = staging en la misma máquina, sin nube
        appPort       : 8080,
        healthPath    : '/actuator/health',
        openapiPath   : '/v3/api-docs',
        aprobadores   : 'admin',           // usuarios Jenkins que pueden aprobar la liberación
        templatesRef  : '',                // vacío = DEVSECOPS_LIB_REF del .env
    ] + cfg

    pipeline {
        agent any
        options {
            timestamps()
            disableConcurrentBuilds()
            buildDiscarder(logRotator(numToKeepStr: '20'))
            timeout(time: 90, unit: 'MINUTES')
        }
        environment {
            GRUPO           = "${c.grupo}"
            FAIL_ON         = "${c.failOn}"
            APP_DIR         = "${c.appDir}"
            IAC_DIR         = "${c.iacDir}"
            DOCKERFILE      = "${c.dockerfile}"
            SEMGREP_CONFIGS = "${c.semgrepConfigs}"
            APP_PORT        = "${c.appPort}"
            HEALTH_PATH     = "${c.healthPath}"
            OPENAPI_PATH    = "${c.openapiPath}"
            TEMPLATES_REF   = "${c.templatesRef}"
            // Versiones fijadas (las mismas que el pipeline de GitHub Actions, fase 1)
            IMG_GITLEAKS = 'ghcr.io/gitleaks/gitleaks:v8.30.0'
            IMG_TRIVY    = 'aquasec/trivy:0.76.1'
            IMG_SEMGREP  = 'semgrep/semgrep:1.182.1'
            IMG_CHECKOV  = 'bridgecrew/checkov:3.3.30'
            IMG_MAVEN    = 'maven:3.9-eclipse-temurin-21'
            IMG_ZAP      = 'ghcr.io/zaproxy/zaproxy:stable'
            IMG_CURL     = 'curlimages/curl:8.11.1'
            SPOTBUGS_VERSION    = '4.10.4'
            FINDSECBUGS_VERSION = '1.14.0'
            TRIVY_DB_REPOSITORY      = 'mirror.gcr.io/aquasec/trivy-db'
            TRIVY_JAVA_DB_REPOSITORY = 'mirror.gcr.io/aquasec/trivy-java-db'
            // Fuera del workspace para que los escáneres no analicen los reportes ni la plantilla
            TPL     = "${env.WORKSPACE}@tmp/devsecops-templates"
            REPORTS = "${env.WORKSPACE}@tmp/reports"
        }
        stages {
            stage('Preparar') {
                steps {
                    sh '''
                        rm -rf "$TPL" "$REPORTS" devsecops-reporte && mkdir -p "$REPORTS"
                        REF="${TEMPLATES_REF:-${DEVSECOPS_LIB_REF:-main}}"
                        git clone -q --depth 1 -b "$REF" "https://github.com/$GITHUB_ORG/devsecops-templates.git" "$TPL"
                        echo "Plantilla devsecops-templates@$REF"
                    '''
                }
            }

            // ------------------------------------------------------------ INTEGRACIÓN
            stage('Build') {
                steps {
                    sh '''
                        docker run --rm --volumes-from jenkins -w "$WORKSPACE/$APP_DIR" "$IMG_MAVEN" \
                          sh -c 'mvn -B -ntp -DskipTests package && mvn -B -ntp -q dependency:build-classpath -Dmdep.outputFile=.devsecops-cp.txt'
                    '''
                }
            }
            stage('Escaneos de seguridad') {
                parallel {
                    stage('SEC · Gitleaks') {
                        steps {
                            sh '''
                                docker run --rm --volumes-from jenkins "$IMG_GITLEAKS" dir "$WORKSPACE" --redact --exit-code 0 \
                                  --report-format sarif --report-path "$REPORTS/gitleaks.sarif"
                            '''
                        }
                    }
                    stage('SEC · Semgrep') {
                        steps {
                            sh '''
                                ARGS=""; for x in $SEMGREP_CONFIGS; do ARGS="$ARGS --config $x"; done
                                docker run --rm --volumes-from jenkins -w "$WORKSPACE" "$IMG_SEMGREP" \
                                  semgrep scan $ARGS --metrics=off --sarif --output "$REPORTS/semgrep.sarif" "$WORKSPACE/$APP_DIR"
                            '''
                        }
                    }
                    stage('SEC · Checkov') {
                        steps {
                            sh '''
                                if [ -d "$IAC_DIR" ]; then
                                  mkdir -p "$REPORTS/ck1"
                                  docker run --rm --volumes-from jenkins "$IMG_CHECKOV" -d "$WORKSPACE/$IAC_DIR" --framework terraform \
                                    --quiet --soft-fail -o sarif --output-file-path "$REPORTS/ck1"
                                  mv "$REPORTS/ck1/results_sarif.sarif" "$REPORTS/checkov.sarif"
                                fi
                                if [ -f "$DOCKERFILE" ]; then
                                  mkdir -p "$REPORTS/ck2"
                                  docker run --rm --volumes-from jenkins "$IMG_CHECKOV" -f "$WORKSPACE/$DOCKERFILE" --framework dockerfile \
                                    --quiet --soft-fail -o sarif --output-file-path "$REPORTS/ck2"
                                  mv "$REPORTS/ck2/results_sarif.sarif" "$REPORTS/checkov-dockerfile.sarif"
                                fi
                            '''
                        }
                    }
                    stage('SEC · SpotBugs') {
                        steps {
                            sh '''
                                T="$JENKINS_HOME/tools/spotbugs-$SPOTBUGS_VERSION"
                                if [ ! -f "$T/findsecbugs.jar" ]; then
                                  mkdir -p "$T"
                                  curl -sSLf "https://github.com/spotbugs/spotbugs/releases/download/$SPOTBUGS_VERSION/spotbugs-$SPOTBUGS_VERSION.tgz" | tar -xz -C "$T"
                                  curl -sSLf -o "$T/findsecbugs.jar" "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/$FINDSECBUGS_VERSION/findsecbugs-plugin-$FINDSECBUGS_VERSION.jar"
                                fi
                                CLASSES=$(find "$WORKSPACE/$APP_DIR" -type d \\( -path '*/target/classes' -o -path '*/build/classes/java/main' \\) | tr '\\n' ' ')
                                CP=$(find "$WORKSPACE/$APP_DIR" -name .devsecops-cp.txt -exec cat {} \\; | tr '\\n' ':')
                                docker run --rm --volumes-from jenkins "$IMG_MAVEN" java -jar "$T/spotbugs-$SPOTBUGS_VERSION/lib/spotbugs.jar" \
                                  -textui -quiet -effort:max -low -pluginList "$T/findsecbugs.jar" \
                                  -include "$TPL/policies/spotbugs-security-include.xml" \
                                  ${CP:+-auxclasspath "$CP"} -sarif="$REPORTS/spotbugs.sarif" $CLASSES
                            '''
                        }
                    }
                    stage('SEC · Trivy (dependencias)') {
                        steps {
                            sh '''
                                docker run --rm --volumes-from jenkins -e TRIVY_DB_REPOSITORY -e TRIVY_JAVA_DB_REPOSITORY "$IMG_TRIVY" \
                                  rootfs --scanners vuln --format sarif --output "$REPORTS/trivy-fs.sarif" "$WORKSPACE/$APP_DIR"
                                docker run --rm --volumes-from jenkins "$IMG_TRIVY" rootfs --skip-db-update --skip-java-db-update \
                                  --format cyclonedx --output "$REPORTS/sbom.cdx.json" "$WORKSPACE/$APP_DIR"
                            '''
                        }
                    }
                }
            }
            stage('Gate de integración') {
                steps {
                    sh '''
                        export GITHUB_REPOSITORY="$GITHUB_ORG/${JOB_NAME%%/*}" GITHUB_SHA="$GIT_COMMIT" GITHUB_REF_NAME="$BRANCH_NAME"
                        export DEVSECOPS_GRUPO="$GRUPO"
                        python3 "$TPL/scripts/normalize_gate.py" --reports "$REPORTS" --scope ci --fail-on "$FAIL_ON" \
                          --app-dir "$APP_DIR" --suppressions .devsecops/suppressions.yml \
                          --out "$REPORTS/hallazgos-ci.json" --metrics-out "$REPORTS/metricas-ci.json" \
                          --summary "$REPORTS/resumen-ci.md" --html "$REPORTS/reporte-ci.html" --enforce
                    '''
                }
            }

            // ------------------------------------------------------------ SOLO EN MAIN
            stage('Build de imagen') {
                when { branch 'main' }
                steps {
                    sh '''
                        docker build -q -f "$DOCKERFILE" -t "devsecops/$GRUPO:$GIT_COMMIT" "$APP_DIR"
                        docker run --rm --volumes-from jenkins -e TRIVY_DB_REPOSITORY -e TRIVY_JAVA_DB_REPOSITORY "$IMG_TRIVY" \
                          image --scanners vuln --format sarif --output "$REPORTS/trivy-image.sarif" "devsecops/$GRUPO:$GIT_COMMIT"
                        export GITHUB_REPOSITORY="$GITHUB_ORG/${JOB_NAME%%/*}" GITHUB_SHA="$GIT_COMMIT" DEVSECOPS_GRUPO="$GRUPO"
                        python3 "$TPL/scripts/normalize_gate.py" --reports "$REPORTS" --scope image --fail-on "$FAIL_ON" \
                          --app-dir "$APP_DIR" --suppressions .devsecops/suppressions.yml \
                          --out "$REPORTS/hallazgos-image.json" --metrics-out "$REPORTS/metricas-image.json" \
                          --summary "$REPORTS/resumen-image.md" --html "$REPORTS/reporte-imagen.html" --enforce
                    '''
                }
            }
            stage('Staging local + DAST') {
                when { allOf { branch 'main'; expression { c.deploy == 'local' } } }
                steps {
                    sh '''
                        NET="stg-$GRUPO-$BUILD_NUMBER"
                        docker network create "$NET" >/dev/null
                        docker run -d --name "$NET-app" --network "$NET" --network-alias app \
                          -e SERVER_PORT="$APP_PORT" -e SPRING_PROFILES_ACTIVE=staging "devsecops/$GRUPO:$GIT_COMMIT" >/dev/null
                        for _ in $(seq 1 40); do
                          if docker run --rm --network "$NET" "$IMG_CURL" -fsS -o /dev/null "http://app:$APP_PORT$HEALTH_PATH"; then
                            echo "Aplicación lista en el staging local"; break
                          fi
                          sleep 5
                        done
                        docker run --rm --network "$NET" "$IMG_CURL" -fsS -o /dev/null "http://app:$APP_PORT$HEALTH_PATH" \
                          || { echo "La aplicación no respondió"; docker logs --tail 50 "$NET-app"; exit 1; }

                        API=""
                        if [ -n "$OPENAPI_PATH" ] && docker run --rm --network "$NET" "$IMG_CURL" -fsS -o /dev/null "http://app:$APP_PORT$OPENAPI_PATH"; then
                          API="zap-api-scan.py -t http://app:$APP_PORT$OPENAPI_PATH -f openapi -J zap-api.json -I;"
                        fi
                        docker run --rm --user root --network "$NET" --volumes-from jenkins "$IMG_ZAP" sh -c "
                          mkdir -p /zap/wrk && cd /zap &&
                          zap-baseline.py -t http://app:$APP_PORT -J zap-baseline.json -I;
                          $API
                          cp /zap/wrk/zap-*.json '$REPORTS/' 2>/dev/null; true"
                    '''
                }
                post {
                    always {
                        sh '''
                            NET="stg-$GRUPO-$BUILD_NUMBER"
                            docker rm -f "$NET-app" >/dev/null 2>&1 || true
                            docker network rm "$NET" >/dev/null 2>&1 || true
                            echo "Staging local destruido"
                        '''
                    }
                }
            }
            stage('Reporte consolidado') {
                when { branch 'main' }
                steps {
                    sh '''
                        export GITHUB_REPOSITORY="$GITHUB_ORG/${JOB_NAME%%/*}" GITHUB_SHA="$GIT_COMMIT" DEVSECOPS_GRUPO="$GRUPO"
                        python3 "$TPL/scripts/normalize_gate.py" --reports "$REPORTS" --scope all --fail-on "$FAIL_ON" \
                          --app-dir "$APP_DIR" --suppressions .devsecops/suppressions.yml \
                          --out "$REPORTS/hallazgos.json" --metrics-out "$REPORTS/metricas.json" \
                          --summary "$REPORTS/resumen.md" --html "$REPORTS/reporte.html" --enforce
                    '''
                }
            }
            stage('Aprobación de liberación') {
                when { branch 'main' }
                steps {
                    catchError(buildResult: 'SUCCESS', stageResult: 'ABORTED') {
                        timeout(time: 30, unit: 'MINUTES') {
                            input message: '¿Aprobar la liberación de esta imagen?', ok: 'Aprobar', submitter: c.aprobadores
                        }
                        sh 'docker tag "devsecops/$GRUPO:$GIT_COMMIT" "devsecops/$GRUPO:approved-$GIT_COMMIT" && echo "Imagen aprobada"'
                    }
                }
            }
        }
        post {
            always {
                sh '''
                    mkdir -p devsecops-reporte
                    cp "$REPORTS"/*.json "$REPORTS"/*.sarif "$REPORTS"/*.md "$REPORTS"/*.html devsecops-reporte/ 2>/dev/null || true
                    cat devsecops-reporte/resumen*.md 2>/dev/null || true
                    # Resumen de una línea para la página del build
                    python3 - <<'PY' > devsecops-reporte/descripcion.txt || true
import json, glob, os
partes = []
for alcance, nombre in (("ci", "Integración"), ("image", "Imagen"), ("", "Global")):
    f = f"devsecops-reporte/hallazgos{'-' + alcance if alcance else ''}.json"
    if not os.path.exists(f):
        continue
    d = json.load(open(f))
    hs = d.get("hallazgos", [])
    ok = d["gate"]["resultado"] == "aprobado"
    partes.append(f"{nombre}: {'APROBADO' if ok else 'BLOQUEADO'}"
                  f" (abiertos {sum(1 for h in hs if h['estado'] == 'abierto')},"
                  f" bloqueantes {d['gate']['bloqueantes']},"
                  f" suprimidos {sum(1 for h in hs if h['estado'] == 'suprimido')})")
print((" · ".join(partes) + " · Detalle: Build Artifacts › devsecops-reporte › reporte*.html") if partes else "Sin reporte (el pipeline falló antes del gate)")
PY
                '''
                script {
                    def desc = fileExists('devsecops-reporte/descripcion.txt') ? readFile('devsecops-reporte/descripcion.txt').trim() : ''
                    if (env.BRANCH_NAME == 'main' && sh(script: 'docker image inspect "devsecops/$GRUPO:approved-$GIT_COMMIT" >/dev/null 2>&1', returnStatus: true) == 0) {
                        desc += ' · Imagen aprobada'
                    }
                    currentBuild.description = desc
                }
                archiveArtifacts artifacts: 'devsecops-reporte/**', allowEmptyArchive: true, fingerprint: false
                script {
                    if (env.BRANCH_NAME == 'main') {
                        // Limpieza: conservar solo las 5 imágenes más recientes del grupo (y sus etiquetas approved-)
                        sh '''
                            docker images "devsecops/$GRUPO" --format '{{.Tag}}' | grep -v '^approved-' | tail -n +6 | while read -r t; do
                              docker rmi "devsecops/$GRUPO:approved-$t" >/dev/null 2>&1 || true
                              docker rmi "devsecops/$GRUPO:$t" >/dev/null 2>&1 || true
                            done
                            docker image prune -f >/dev/null
                            echo "Imágenes del grupo conservadas:"; docker images "devsecops/$GRUPO" --format '  {{.Tag}}  {{.Size}}'
                        '''
                    }
                }
            }
        }
    }
}
