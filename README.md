# AVUS tool

[![Build Status](https://travis-ci.org/REDACTED/avus.svg)](https://travis-ci.org/REDACTED/avus)

This tool allows for re-evaluating a list of vulnerability findings.
It does that by providing the basic infrastructure for

1. reading a report (in CSV format, as provided by other means, [see below](#supported-report-types)),
2. re-evaluating its _severity_ score, by calling out to user-provided functions that can modify the parameters of the rating (using CVSS v2), and
3. outputting the resulting list.

```raw
               +---+
               | ? |
               +-+-+
                 |
                 v
+-----+      +-------+     +-----+
| CSV | -->  | AVUS  | --> | CSV |
+-----+      +-------+     +-----+
```

The knack is that _anything_ can fill the place of the question mark, i.e., change how findings are evaluated.
A basic, static example is given in `examples/avus.hs`, where the parameters of both the base and environment CVSS scoring are determined using a simple security concept.

The mechanism used for this feature is provided by [`Config.Dyre`](http://hackage.haskell.org/package/dyre) (see `src/Avus.hs`)

Furthermore, it includes a static mapping of CWE IDs (as read from the findings CSV) to partial/complete impacts (in `src/Avus/CWE.hs`, TODO: autogenerate).

## Usage

```raw
Usage: avus [OPTION...] [FILE]
  -V        --version     show version information
  -o[FILE]  --out[=FILE]  output to FILE (defaults to stdout)
```

## Supported report types

As of now, only the CSV input that is created with [ThreadFix' CLI importer](https://github.com/denimgroup/threadfix/wiki/CLI-Importers) is supported.
Furthermore, the CSV file needs to be preprocessed (see `examples/prep.awk`).
The rare entries without a CWE ID are passed through unchanged.

AVUS is copyright © 2015 Fraunhofer AISEC, and released to the public under the terms of the MIT license.
