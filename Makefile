all:	mydump

mydump:
	g++ -c src/mydump.cpp -o bin/mydump -lpcap

clean:
	rm bin/mydump
