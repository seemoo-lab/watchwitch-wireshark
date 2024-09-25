#!/bin/sh

for file in $(ls ./lua/); do
	ln -s $(pwd)/lua/$file ~/.local/lib/wireshark/plugins/$file
done
