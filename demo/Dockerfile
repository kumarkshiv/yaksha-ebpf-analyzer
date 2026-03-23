FROM ubuntu:jammy
RUN apt update
ENV DEBIAN_FRONTEND=noninteractive
RUN apt -y install iputils-ping
RUN apt -y install hping3
RUN apt -y install iproute2
RUN apt -y install net-tools
RUN apt update
RUN apt -y install python3-scapy