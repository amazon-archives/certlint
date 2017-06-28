require "mkmf"

dir_config("certlint_ext")

$srcs = Dir["*.c"]

create_makefile("certlint_ext")
