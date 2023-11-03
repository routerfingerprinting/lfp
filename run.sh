#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 list_of_ips_file output_file.json"
    exit 1
fi

list_of_ips_file="$1"
output_file="$2"


while read -r IP; do
    for i in {1..3}; do
        for probe in "icmp-echo" "tcp-ack" "udp -B 0000000000000000000000000000000000000000"; do
            scamper -c "ping -c 1 -P $probe" -i "$IP" -O json >> "$output_file"
        done
    done
done < "$list_of_ips_file"
