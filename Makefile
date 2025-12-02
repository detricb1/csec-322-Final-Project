all:
  make finalServer
  make finalClient

# ======== Server Build ========

finalServer: finalServer.o diffieHellman.o xor.o
	g++ -o finalServer finalServer.o diffieHellman.o xor.o

finalServer.o: finalServer.cc finalPacket.h diffieHellman.h xor.h
	g++ -c finalServer.cc

# ======== Client Build ========

finalClient: finalClient.o diffieHellman.o xor.o
	g++ -o finalClient finalClient.o diffieHellman.o xor.o

finalClient.o: finalClient.cc finalPacket.h diffieHellman.h xor.h
	g++ -c finalClient.cc

# ======== Crypto Modules ========

diffieHellman.o: diffieHellman.cc diffieHellman.h
	g++ -c diffieHellman.cc

xor.o: xor.cc xor.h
	g++ -c xor.cc

# ======== Helper Modules ========

socket.o: socket.cc socket.h
g++ -c socket.cc

selector.o: selector.cc selector.h
g++ -c selector.cc

# ======== Clean ========

clean:
	rm -f *.o finalServer finalClient
