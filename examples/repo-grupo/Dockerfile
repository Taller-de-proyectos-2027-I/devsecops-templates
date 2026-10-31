# --- Etapa 1: compilación -----------------------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -B -ntp dependency:go-offline
COPY src ./src
RUN mvn -B -ntp -DskipTests package

# --- Etapa 2: ejecución (imagen mínima y usuario sin privilegios) --------------
FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache curl \
 && addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -fsS http://localhost:8080/actuator/health || exit 1
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
