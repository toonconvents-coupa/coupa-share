FROM alfresco/alfresco-base-tomcat:8.5.28-java-8-oracle-centos-7
#FROM alfresco/alfresco-base-tomcat:8.5.34-java-11-openjdk-centos-7

RUN mkdir -p /usr/local/tomcat/shared/classes/alfresco/web-extension
RUN mkdir -p /usr/local/tomcat/amps_share
RUN mkdir /licenses

COPY target/war /usr/local/tomcat/webapps
COPY target/alfresco-mmt/* /usr/local/tomcat/alfresco-mmt/
COPY target/amps_share /usr/local/tomcat/amps_share

COPY target/classes/web-extension-samples/share-config-custom.xml /usr/local/tomcat/shared/classes/alfresco/web-extension
COPY target/classes/web-extension-samples/custom-slingshot-application-context.xml.sample /usr/local/tomcat/shared/classes/alfresco/web-extension
COPY target/classes/web-extension-samples/smartfolders-amp-actions-config.xml /usr/local/tomcat/shared/classes/alfresco/web-extension

COPY target/licenses/* /licenses/

# Up the Tomcat cache
RUN sed -i 's/<\/Context>/\n<Resources cachingAllowed="true" cacheMaxSize="100000" \/>\n<\/Context>/' /usr/local/tomcat/conf/context.xml

# not sure if this is needed for share:
RUN sed -i "s/shared.loader=/shared.loader=\${catalina.base}\/shared\/classes/" /usr/local/tomcat/conf/catalina.properties

COPY substituter.sh /usr/local/tomcat/shared/classes/alfresco
RUN chmod +x /usr/local/tomcat/shared/classes/alfresco/substituter.sh

# apply amps
RUN java -jar /usr/local/tomcat/alfresco-mmt/alfresco-mmt*.jar install \
              /usr/local/tomcat/amps_share /usr/local/tomcat/webapps/share -directory -nobackup -force

ENTRYPOINT ["/usr/local/tomcat/shared/classes/alfresco/substituter.sh", "catalina.sh run"]

EXPOSE 8000
