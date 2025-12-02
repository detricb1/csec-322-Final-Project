all:
	make finalServer
	make finalClient

finalServer: finalServer.o diffieHellman.o xor.o socket.o selector.o
	g++ -o finalServer finalServer.o diffieHellman.o xor.o socket.o selector.o

finalServer.o: finalServer.cc finalPacket.h diffieHellman.h xor.h socket.h selector.h
	g++ -c finalServer.cc


finalClient: finalClient.o diffieHellman.o xor.o socket.o
	g++ -o finalClient finalClient.o diffieHellman.o xor.o socket.o

finalClient.o: finalClient.cc finalPacket.h diffieHellman.h xor.h socket.h
	g++ -c finalClient.cc


diffieHellman.o: diffieHellman.cc diffieHellman.h
	g++ -c diffieHellman.cc

xor.o: xor.cc xor.h
	g++ -c xor.cc

socket.o: socket.cc socket.h
	g++ -c socket.cc

selector.o: selector.cc selector.h
	g++ -c selector.cc


clean:
rm -f *.o finalServer finalClient
