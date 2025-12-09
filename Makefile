all:
	make finalServer
	make finalClient

# ======== Server ========

finalServer: finalServer.o ../tools/socket.o ../tools/selector.o diffieHellman.o xor.o
	g++ -o finalServer finalServer.o ../tools/socket.o ../tools/selector.o diffieHellman.o xor.o

finalServer.o: finalServer.cc finalPacket.h diffieHellman.h xor.h
	g++ -c -I ../tools finalServer.cc

# ======== Client ========

finalClient: finalClient.o ../tools/socket.o ../tools/selector.o diffieHellman.o xor.o
	g++ -o finalClient finalClient.o ../tools/socket.o ../tools/selector.o diffieHellman.o xor.o

finalClient.o: finalClient.cc finalPacket.h diffieHellman.h xor.h
	g++ -c -I ../tools finalClient.cc

# ======== Crypto Modules ========

diffieHellman.o: diffieHellman.cc diffieHellman.h
	g++ -c diffieHellman.cc

xor.o: xor.cc xor.h
	g++ -c xor.cc
