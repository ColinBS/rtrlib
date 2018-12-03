#!/bin/bash

echo "pathlen,time" > performance-results.csv

for ((i = 1; i <= $1; i++))
do
    ../build/tests/test_bgpsec_performance >> performance-results.csv
done
