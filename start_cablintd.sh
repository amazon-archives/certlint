#!/bin/bash
for i in `seq 1 $1`;
do
  ruby -I /usr/local/certlint/lib /usr/local/certlint/bin/cablintd $i &
done

sleep 3

for i in `seq 1 $1`;
do
  chmod 666 /tmp/cablint.socket$i
done
