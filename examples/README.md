# Example avus project

## Prerequisites

For using avus, a Haskell installation is needed, for example using [Haskell Platform](https://www.haskell.org/platform/), or [MinGHC](https://github.com/fpco/minghc).
Having obtained it, run `cabal update` to update cabal's package list.

## Install avus

```
git clone git://github.com/srenatus/avus
cd avus
cabal install
```

## Execute avus

Note that the location where `avus` was installed in the previous step must be part of your `$PATH` variable:

```
avus sample.csv > sample-new.csv
```
