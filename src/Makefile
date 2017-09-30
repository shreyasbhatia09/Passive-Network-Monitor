all: mydump

mydump: mydump.o
    g++ mydump.o -o mydump

mydump.o: main.cpp
    g++ -c main.cpp

clean:
    rm *o hello
