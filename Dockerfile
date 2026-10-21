FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B -q -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -B --no-transfer-progress -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
RUN keytool -genkeypair -alias test-seal -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -dname "CN=DSS Test Seal,O=Example,C=NL" -validity 365 -storetype PKCS12 -keystore /app/test-seal.p12 -storepass changeit -keypass changeit -noprompt
COPY --from=build /build/target/external-sdjwt-1.0-SNAPSHOT.jar /app/app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
