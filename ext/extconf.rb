require "mkmf"

dir_config("asn1validator")

$srcs = Dir["*.c"]

create_makefile("asn1validator")
