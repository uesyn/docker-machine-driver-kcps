#
# Makefile for docker-machine-driver-kcps
#

all:
	go build  -a -tags netgo -installsuffix netgo --ldflags '-extldflags "-static"' -o docker-machine-driver-kcps ./bin

clean:
	rm docker-machine-driver-kcps
