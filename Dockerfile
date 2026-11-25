FROM tomcat:11.0.24-jre21-temurin

WORKDIR /usr/local/tomcat

# Remove default tomcat sample apps
RUN rm -rf webapps/* webapps.dist

# Direct Tomcat internal logs (catalina, localhost, manager) to shared volume (/logs)
RUN sed -i 's|\${catalina.base}/logs|/logs|g' conf/logging.properties

# Ensure /logs directory exists on container boot before Tomcat starts logging
RUN echo "mkdir -p /logs" > bin/setenv.sh && chmod +x bin/setenv.sh

# Copy minimal HTTPS server.xml
COPY server.xml conf/server.xml

# Copy the pre-built ROOT.war
COPY target/ROOT.war webapps/ROOT.war

# Create mount points for SSL and persistent storage
RUN mkdir -p /usr/local/tomcat/ssl /data /logs

# Telling Tomcat to use Environment Variables
RUN echo "org.apache.tomcat.util.digester.PROPERTY_SOURCE=org.apache.tomcat.util.digester.EnvironmentPropertySource" >> conf/catalina.properties

# Mitigate Java4Shell (CVE-2026-114938) Base64 intrinsic vulnerability
ENV CATALINA_OPTS="-XX:-UseBASE64Intrinsics"

EXPOSE 443

CMD ["catalina.sh", "run"]