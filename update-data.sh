#!/bin/bash
curl -o data/newgtlds.csv https://newgtlds.icann.org/newgtlds.csv
curl -o data/root.zone http://www.internic.net/domain/root.zone
curl -o data/special-use-domain.csv http://www.iana.org/assignments/special-use-domain-names/special-use-domain.csv
curl -o data/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat
