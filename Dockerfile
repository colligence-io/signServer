FROM ubuntu:bionic

RUN apt-get update && apt-get install -y wget libntl-dev libboost-serialization-dev libboost-random-dev git build-essential gcc g++ make cmake

WORKDIR /
RUN wget https://dl.google.com/go/go1.12.5.linux-amd64.tar.gz
RUN tar -xvf go1.12.5.linux-amd64.tar.gz
RUN rm go1.12.5.linux-amd64.tar.gz

ENV GOPATH=/go
ENV PATH=/go/bin:$PATH

WORKDIR /build
ADD . .
RUN go build
RUN mkdir -p /tss/trustSigner
RUN cp /build/signServer /tss
RUN cp /build/trustSigner/libtrustsigner.so /tss/trustSigner
RUN rm -rf /build

ENV TSS_PATH /tss

EXPOSE 3456
VOLUME ["/tss/log", "/tss/etc"]

CMD ["/tss/signServer", "server"]