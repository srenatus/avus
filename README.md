# RIVUM tool

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
| CSV | -->  | RIVUM | --> | CSV |
+-----+      +-------+     +-----+
```

The knack is that _anything_ can fill the place of the question mark, i.e., change how findings are evaluated.
A basic, static example is given in `examples/rivum.hs`, where the parameters of both the base and environment CVSS scoring are determined using a simple security concept.

The mechanism used for this feature is provided by [`Config.Dyre`](http://hackage.haskell.org/package/dyre) (see `src/Rivum.hs`)

Furthermore, it includes a static mapping of CWE IDs (as read from the findings CSV) to partial/complete impacts (in `src/Rivum/CWE.hs`, TODO: autogenerate).

## Supported report types

As of now, only the CSV input that is created with [ThreadFix' CLI importer](https://github.com/denimgroup/threadfix/wiki/CLI-Importers) is supported.
Futhermore, the CSV file needs to be preprocessed (TODO).
The rare entries without a CWE ID are passed through unchanged.

RIVUM is copyright © 2015 Fraunhofer AISEC, and released to the public under the terms of the MIT license.
