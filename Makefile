CC= gcc
RM= rm -vf
CPPFLAGS= -I.
SRCFILES= src/mydump.cpp
OUTPUTFILES = bin/mydump
LIBFLAG = -lpcap

.PHONY: all clean

all:
	g++  -I.  $(SRCFILES) -o $(OUTPUTFILES) $(LIBFLAG)

clean:
	$(RM) $(OUTPUTFILES)
