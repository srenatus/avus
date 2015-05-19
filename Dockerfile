FROM haskell:latest

RUN mkdir -p /opt/rivum

ENV PATH /root/.cabal/bin:$PATH
WORKDIR /opt/rivum

ADD . /opt/rivum
RUN cabal update && cabal install

WORKDIR /opt/rivum/examples
RUN rivum "xv6.csv" --dyre-debug
