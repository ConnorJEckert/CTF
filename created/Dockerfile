FROM alpine

# Get deps
RUN apk add --no-cache python3-dev py3-pip curl grep

# Create the user user
RUN addgroup -g 1000 -S user && adduser -S user -G user -s /bin/sh -u 1000 user
RUN sed -i -e 's/^user:!:/user:*:/' /etc/shadow

# Copy source files
COPY mount /svc/mount
RUN python3 -m pip install flask

# COPY in the scripts
COPY docker-entrypoint.sh /root/docker-entrypoint.sh
COPY health.sh /root/health.sh
RUN echo "flag{}" > /svc/flag.txt

# Call the entrypoint
EXPOSE 1234
ENTRYPOINT /root/docker-entrypoint.sh
