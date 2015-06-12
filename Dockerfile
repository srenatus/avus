FROM haskell:latest

RUN mkdir -p /opt/avus

ENV PATH /root/.cabal/bin:$PATH
WORKDIR /opt/avus

ADD . /opt/rivum
RUN cabal update && cabal install --only-dependencies --enable-tests
#RUN cabal configure --enable-tests && cabal build && cabal test && cabal install

#WORKDIR /opt/rivum/examples
#RUN avus "xv6.csv" --dyre-debug
