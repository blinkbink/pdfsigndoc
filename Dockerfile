FROM sgrio/java:jre_8_alpine
COPY kms.jar /home/kms.jar
COPY admin.jks /opt/jks/admin.jks
COPY truststore.jks /opt/jks/truststore.jks
COPY serverKMS.jks /opt/jks/serverKMS.jks
COPY testerkeystore /opt/jks/testerkeystore
COPY KeyStore.jks /opt/jks/KeyStore.jks
COPY tomcat-digisign.jks /opt/jks/tomcat-digisign.jks
COPY digisign-id.jks /opt/jks/digisign-id.jks
COPY Test.pdf /opt/sealTestFile/Test.pdf
CMD ["java","-jar","/home/kms.jar"]
