# Use nextgenhealthcare/connect as the base image
FROM nextgenhealthcare/connect:latest

# Copy the jose4j library version 0.9.5 to the specified directory in the container
COPY lib/jose4j-0.9.5.jar /opt/mirthconnect/appdata/jars/

# Ensure permissions are set correctly for the Mirth Connect process to access the JAR
RUN chown mirth:mirth /opt/mirthconnect/appdata/jars/jose4j-0.9.5.jar && \
    chmod 644 /opt/mirthconnect/appdata/jars/jose4j-0.9.5.jar

# If Mirth Connect does not automatically recognize the JAR, you might need to add it to the classpath
# Uncomment the line below and adjust as necessary
# ENV CLASSPATH=$CLASSPATH:/opt/mirthconnect/appdata/jars/jose4j-0.9.5.jar

# Other customizations or configurations can go here
