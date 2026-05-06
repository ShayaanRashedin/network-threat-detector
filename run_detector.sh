#!/bin/bash

echo "Starting Network Threat Detector"
echo "--------------------------------"

python main.py "$@"

if [ $? -eq 0 ]; then
    echo "Detection run completed successfully."
else
    echo "Detection run failed."
    exit 1
fi