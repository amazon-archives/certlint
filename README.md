# certlint
X.509 certificate linter

certlint is currently at version 0.0.1.  It does not yet build as a gem.  For now, execute by running:

`ruby -I lib bin/certlint` or `ruby -I lib bin/cablint`

## Required gems

* public_suffix
* open4
* simpleidn
* iconv

If using less than Ruby 2.3, you also need the `unf` gem.

## Building certlint-x509helper

certlint requires that the program certlint-x509helper be in your path and executable.

See build-x509helper/README for instructions on building it.
 
