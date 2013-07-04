#!/bin/bash
set -x
set -e
#test1
groovy -cp src/groovy src/groovy/convert.groovy test/out test/ test/rundeck-config.properties -adhoc read,run

cd test/out
result=0
for i in *.aclpolicy ; do 
    diff -q $i ../expected/$i
done

