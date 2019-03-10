# certlint
X.509 certificate linter

`certlint` is currently at version 0.9.0.  It does not yet build as a gem.

For now, execute by running:

`ruby -I lib:ext bin/certlint` or `ruby -I lib:ext bin/cablint`

Add '-CAA' flag to get CAA information. Note: -CAA flag MUST be at the very end.

`ruby -I lib:ext bin/certlint <certfile> -CAA` or `ruby -I lib:ext bin/cablint <certfile1> <certfile2> -CAA`

## Required gems

* `public_suffix`
* `simpleidn`

If using less than Ruby 2.3, you also need the `unf` gem.

## Building the asn1validator extension

`certlint` requires that the `asn1validator` extension be available.

See ext/README for instructions on building it.

## Output

Messages will be output one per line.  Each line will start with a single
capital letter, a colon, and a space. The letters indicate the type of message:

* B: Bug. Your certificate has a feature not handled by certlint.
* I: Information.  These are purely informational; no action is needed.
* N: Notice.  These are items known to cause issues with one or more implementations of certificate processing but are not errors according to the standard.
* W: Warning.  These are issues where a standard recommends differently but the standard uses terms such as "SHOULD" or "MAY".
* E: Error.  These are issues where the certificate is not compliant with the standard.
* F: Fatal Error.  These errors are fatal to the checks and prevent most further checks from being executed.  These are extremely bad errors.
* CAA: Real-time CAA information for a domain (not CAA info when the cert was issued). It also specifies whether the CAA RR was encountered in the primary domain, CNAME, or hierarchy.

## Thanks

Certlint was written by Peter Bowen (pzbowen@gmail.com).

Contributors include Matt Palmer, Rob Stradling, David Keeler, and Karsten Weiss.
