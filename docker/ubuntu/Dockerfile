FROM ubuntu:precise-20151020
COPY sources.list  /etc/apt/sources.list
RUN apt-get update && \
    apt-get -y install bluez bluez-tools bluez-utils bluetooth rfkill
COPY docker_entrypoint.sh /root
RUN sh /root/docker_entrypoint.sh
