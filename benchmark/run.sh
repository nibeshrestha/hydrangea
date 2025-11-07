#!/bin/bash

RUNS=1
BURSTS=(3500 4000) 

for BURST in ${BURSTS[@]}
do
    for i in $(seq 1 1 "$RUNS")
    do
        if fab remote --client-rate $BURST \
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