FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q dependency:go-offline
COPY src ./src
RUN mvn -q -o package -DskipTests dependency:copy-dependencies -DincludeScope=runtime

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /src/target/classes ./classes
COPY --from=build /src/target/dependency ./lib
ENV PORT=8080 ACCESS_LOG=/app/logs/access.log
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080"]
CMD ["java", "-Dlog4j2.formatMsgNoLookups=true", "-cp", "classes:lib/*", "bank.transaction.App"]
