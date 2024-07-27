# Makefile

# Default target
all: pcap-test

# Link object files to create the executable
pcap-test: pcap-test.o
	gcc -o pcap-test pcap-test.o -lpcap -lnet 

# Compile source files to object files
pcap-test.o: pcap-test.c
	gcc -c -o pcap-test.o pcap-test.c

# Clean up generated files
clean:
	rm -f pcap-test
	rm -f pcap-test.o
