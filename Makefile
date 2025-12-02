all:
	make server
	make client

# ======== Server ========

server: server.o dh.o xor.o
	g++ -o server server.o dh.o xor.o

server.o: server.cc packet.h dh.h xor.h
	g++ -c server.cc

# ======== Client ========

client: client.o dh.o xor.o
	g++ -o client client.o dh.o xor.o

client.o: client.cc packet.h dh.h xor.h
	g++ -c client.cc

# ======== Crypto Modules ========

dh.o: dh.cc dh.h
	g++ -c dh.cc

xor.o: xor.cc xor.h
	g++ -c xor.cc

clean:
	rm -f *.o server client
