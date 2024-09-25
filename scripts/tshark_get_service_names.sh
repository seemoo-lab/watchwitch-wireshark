#!/bin/sh

if [[ "$#" -ne 1 ]]; then
	echo "Usage: ./tshark_get_service_names.sh ../path/to/pklgs/"
	exit 1
fi

DIRECTORY=$1

# set this path to the patched tshark binary
TSHARK="tshark"

echo "All Magnet Service Names:"
for file in $DIRECTORY/*.pklg; do $TSHARK -r $file -T fields -E header=n -e magnet.service_name magnet.service_name; done | tr ',' '\n' | sort | uniq
echo ""

echo "All NWSC Service Names:"
for file in $DIRECTORY/*.pklg; do $TSHARK -r $file -T fields -E header=n -e nwsc.service_name nwsc.service_name; done | tr ',' '\n' | sort | uniq
echo ""

echo "All Alloy Topics:"
for file in $DIRECTORY/*.pklg; do $TSHARK -r $file -T fields -E header=n -e alloy.topic alloy.topic; done | tr ',' '\n' | sort | uniq
echo ""
