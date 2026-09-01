FROM tomcat:11.0.24-jre21-temurin

WORKDIR /usr/local/tomcat

# Remove default tomcat sample apps
RUN rm -rf webapps/* webapps.dist

# Copy minimal HTTPS server.xml
COPY server.xml conf/server.xml

# Copy the pre-built ROOT.war
COPY target/ROOT.war webapps/ROOT.war

# Create mount points for SSL and persistent storage
RUN mkdir -p /usr/local/tomcat/ssl /data

#Telling Tomcat to use Environment Variables
RUN echo "org.apache.tomcat.util.digester.PROPERTY_SOURCE=org.apache.tomcat.util.digester.EnvironmentPropertySource" >> conf/catalina.properties
EXPOSE 443

CMD ["catalina.sh", "run"]