FROM ubuntu:bionic

RUN apt-get update && apt-get install -y wget libntl-dev libboost-serialization-dev libboost-random-dev

WORKDIR /usr/lib
RUN wget https://dl.google.com/go/go1.12.5.linux-amd64.tar.gz
RUN tar -xvf go1.12.5.linux-amd64.tar.gz
RUN rm go1.12.5.linux-amd64.tar.gz
ENV PATH=/usr/lib/go/bin:$PATH

WORKDIR /tss
COPY signServer .
COPY trustSigner/libtrustsigner.so ./trustSigner/libtrustsigner.so

ENV TSS_PATH /tss

EXPOSE 3456
VOLUME ["/tss/log", "/tss/etc"]

CMD ["/tss/signServer", "server"]