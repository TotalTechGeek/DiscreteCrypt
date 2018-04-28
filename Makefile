ifeq ($(OS),Windows_NT)
	CC = g++ -s -static -O3 -std=gnu++11 
	END = cppcrypto/cppcrypto/libcppcrypto.a cryptopp/libcryptopp.a -lssp
else
	CC = g++ -O3 -std=gnu++11 
	END = cppcrypto/cppcrypto/libcppcrypto.a cryptopp/libcryptopp.a -msse2 -fstack-protector -lpthread
endif

all: build/cryptotool.exe

build/cryptotool.exe: build/Parameters.o build/main.o build/SymmetricAuthenticationExtension.o build/AsymmetricAuthenticationExtension.o build/toolCrypto.o
	$(CC) build/main.o build/Parameters.o build/AsymmetricAuthenticationExtension.o build/SymmetricAuthenticationExtension.o build/toolCrypto.o -o build/cryptotool.exe $(END)

build/main.o: tool/main.cpp  
	$(CC) -c tool/main.cpp -o build/main.o $(END)

build/Parameters.o: tool/Parameters.cpp tool/Parameters.h 
	$(CC) -c tool/Parameters.cpp -o build/Parameters.o $(END)

build/SymmetricAuthenticationExtension.o: tool/SymmetricAuthenticationExtension.cpp tool/SymmetricAuthenticationExtension.h 
	$(CC) -c tool/SymmetricAuthenticationExtension.cpp -o build/SymmetricAuthenticationExtension.o $(END)

build/AsymmetricAuthenticationExtension.o: tool/AsymmetricAuthenticationExtension.cpp tool/AsymmetricAuthenticationExtension.h 
	$(CC) -c tool/AsymmetricAuthenticationExtension.cpp -o build/AsymmetricAuthenticationExtension.o $(END)

build/toolCrypto.o: tool/toolCrypto.cpp tool/toolCrypto.h tool/Parameters.h
	$(CC) -c tool/toolCrypto.cpp -o build/toolCrypto.o $(END)
