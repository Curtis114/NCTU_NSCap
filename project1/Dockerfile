FROM ubuntu:18.04

# use Taiwan mirrors
RUN echo \
'deb http://tw.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse\n\
deb http://tw.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse\n\
deb http://tw.archive.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse\n\
deb-src http://tw.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse\n\
deb-src http://tw.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse\n\
deb-src http://tw.archive.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse\n' \
> /etc/apt/sources.list
RUN apt-get update
RUN apt-get install iptables -y
RUN apt-get install iputils-ping -y
RUN apt-get install net-tools -y
RUN apt-get install iproute2 -y
RUN apt-get install tcpdump -y
RUN apt-get install vim -y
RUN apt-get install isc-dhcp-server -y
RUN apt-get install isc-dhcp-client -y
RUN apt-get install mininet -y
RUN apt-get install bridge-utils -y
