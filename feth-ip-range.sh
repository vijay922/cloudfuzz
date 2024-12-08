#!/bin/bash
curl https://raw.githubusercontent.com/femueller/cloud-ip-ranges/refs/heads/master/microsoft-azure-ip-ranges.json | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' > azure-cidr.txt
for cidr in $(cat "azure-cidr.txt") 
do

timeout 5m python3 cloudfuzz.py -cidr $cidr -t 200 >> Azure-Results.txt

done
