FROM spire-dev:latest

RUN apt-get install -y curl vim

WORKDIR /root/spire

ENTRYPOINT ["/bin/sleep"]
CMD ["infinity"]
