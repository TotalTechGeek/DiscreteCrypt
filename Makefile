ifeq ($(OS),Windows_NT)
	CC = g++ -s -static -O3 -std=gnu++11 
	END = cppcrypto/cppcrypto/libcppcrypto.a cryptopp/libcryptopp.a -lssp
else
	CC = g++ -O3 -std=gnu++11 
	END = cppcrypto/cppcrypto/libcppcrypto.a cryptopp/libcryptopp.a -msse2 -fstack-protector -lpthread
endif

all: build/cryptotool.exe

build/cryptotool.exe: build/Parameters.o build/main.o
	$(CC) build/main.o build/Parameters.o -o build/cryptotool.exe $(END)

build/main.o: tool/main.cpp tool/toolCrypto.h
	$(CC) -c tool/main.cpp -o build/main.o $(END)

build/Parameters.o: tool/Parameters.cpp 
	$(CC) -c tool/Parameters.cpp -o build/Parameters.o $(END)
