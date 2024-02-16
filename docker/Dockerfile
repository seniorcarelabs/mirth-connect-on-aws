# Use nextgenhealthcare/connect as the base image
FROM nextgenhealthcare/connect:latest

# Temporarily switch to root to change file permissions
USER root

# Copy the jose4j library version 0.9.5 to the specified directory in the container
COPY lib/jose4j-0.9.5.jar /opt/mirthconnect/appdata/jars/

# Ensure permissions are set correctly for the Mirth Connect process to access the JAR
RUN chown mirth:mirth /opt/mirthconnect/appdata/jars/jose4j-0.9.5.jar && \
    chmod 644 /opt/mirthconnect/appdata/jars/jose4j-0.9.5.jar

