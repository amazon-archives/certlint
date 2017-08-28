require "mkmf"

$CPPFLAGS = "-DASN_DISABLE_OER_SUPPORT -DASN_DISABLE_PER_SUPPORT"

dir_config("asn1validator")

create_makefile("asn1validator")
