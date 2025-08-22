LDLIBS=-lnetfilter_queue

all: netfilter-test


main.o: ip.h main.cpp

ip.o: ip.h ip.cpp

netfilter-test: main.o ip.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f netfilter-test *.o
