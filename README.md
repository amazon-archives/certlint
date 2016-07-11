# certlint
X.509 certificate linter

`certlint` is currently at version 0.1.0.  It does not yet build as a gem.

For now, execute by running:

`ruby -I lib bin/certlint` or `ruby -I lib bin/cablint`

## Required gems

* `public_suffix`
* `open4`
* `simpleidn`

If using less than Ruby 2.3, you also need the `unf` gem.

## Building certlint-x509helper

`certlint` requires that the program `certlint-x509helper` be in your path and
executable.

See `build-x509helper/README` for instructions on building it.

## Output

Messages will be output one per line.  Each line will start with a single
capital letter, a colon, and a space.  The letters indicate the type of message:

```
B: Bug. Your certificate has a feature not handled by certlint.
I: Information.  These are purely informational; no action is needed.
N: Notice.  These are items known to cause issues with one or more implementations of certificate processing but are not errors according to the standard.
W: Warning.  These are issues where a standard recommends differently but the standard uses terms such as "SHUOLD" or "MAY".
E: Error.  These are issues where the certificate is not compliant with the standard.
F: Fatal Error.  These errors are fatal to the checks and prevent most further checks from being executed.  These are extremely bad errors. 
```
