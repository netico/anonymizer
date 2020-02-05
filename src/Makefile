#!/bin/bash


all:
	valac --pkg gtk+-3.0 --pkg gmodule-2.0 "anonymizer.vala" -o anonymizer

clean:
	rm -rf *.o anonymizer

install:
	mkdir -p /usr/share/anonymizer/
	cp -f anonymizer.glade /usr/share/anonymizer
	chmod -R 644 /usr/share/anonymizer/anonymizer.glade
	cp -f anonymizer /usr/bin

uninstall:
	rm -f /usr/bin/anonymizer
	rm -f /usr/share/anonymizer
