FROM ubuntu:16.04

RUN apt-get -y update && apt-get install -y python-pip && apt-get install -y wget

RUN wget -q -O - http://debian.erlyvideo.org/binary/gpg.key | apt-key add -
RUN echo "deb http://debian.erlyvideo.org binary/" > /etc/apt/sources.list.d/erlyvideo.list
RUN apt-get -y update
RUN apt-get -y install flussonic flussonic-ffmpeg flussonic-python

RUN pip install supervisor && apt-get clean autoclean && apt-get autoremove -y

ADD supervisord.conf /etc/supervisord.conf
EXPOSE 80 8080 1935 554
VOLUME ["/var/log/flussonic", "/etc/flussonic"]

CMD ["/usr/local/bin/supervisord"]
