CPPFLAGS = -ggdb

all:
	g++ $(CPPFLAGS) server.cc -o server -lssl -lcrypto -pthread -lhiredis
	g++ $(CPPFLAGS) client.cc -o client -lssl -lcrypto -pthread

cert:
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt
