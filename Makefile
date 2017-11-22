#
# Makefile for docker-machine-driver-kcps
#

all:
	go build -o docker-machine-driver-kcps ./bin

clean:
	rm docker-machine-driver-kcps
