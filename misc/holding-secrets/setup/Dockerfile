FROM ubuntu

RUN apt-get update &&  apt-get -y install git

WORKDIR /root/
RUN git clone https://github.com/thiagoralves/OpenPLC_v3.git


COPY flag.st /root/OpenPLC_v3/webserver/st_files
COPY prep.sh /root
RUN chmod +x /root/prep.sh
RUN /root/prep.sh

WORKDIR /root/OpenPLC_v3
RUN ./install.sh docker

RUN apt-get clean

COPY run.sh /root

RUN chmod +x /root/run.sh

EXPOSE 502
CMD ["/root/run.sh"]