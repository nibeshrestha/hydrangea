#!/bin/bash

RUNS=1
BURSTS=(50 100 150 200 300 400 500 600 700 800) 

for BURST in ${BURSTS[@]}
do
    for i in $(seq 1 1 "$RUNS")
    do
        if fab remote --block-size $BURST \
            | tee /dev/tty \
            | grep -i "error\|exception\|traceback"
        then
            echo "Failed to complete remote benchmark"
            fab kill
            exit 2
        fi
    fab kill
    sleep 20
    done
done