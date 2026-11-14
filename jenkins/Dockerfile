# Jenkins del Taller de Proyectos: controlador con Docker CLI, Python y plugins fijados.
# Se construye con: docker compose build   (ver README.md de esta carpeta)
FROM jenkins/jenkins:lts-jdk21

USER root
# Docker CLI (usa el Docker del host vía socket), git, curl y Python para normalize_gate.py
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg git python3 python3-yaml \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

USER jenkins
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

# Fuera de JENKINS_HOME (volumen persistente): así cada build de la imagen trae la configuración nueva
COPY casc.yaml /usr/share/jenkins/casc.yaml
ENV CASC_JENKINS_CONFIG=/usr/share/jenkins/casc.yaml \
    JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
