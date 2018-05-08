ifeq ($(OS),Windows_NT)
	CC = g++ -O2 -static -s -std=gnu++11 
	END = cryptopp/libcryptopp.a  -lssp -fstack-protector -Wl,--stack,8000000
else
	CC = g++ -O2 -std=gnu++11 
	END = cryptopp/libcryptopp.a -msse2 -fstack-protector -lpthread
endif

all: build/cryptotool.exe

build/cryptotool.exe: build/Parameters.o build/main.o build/SymmetricAuthenticationExtension.o build/AsymmetricAuthenticationExtension.o build/toolCrypto.o 
	$(CC) build/main.o build/Parameters.o build/AsymmetricAuthenticationExtension.o build/SymmetricAuthenticationExtension.o build/toolCrypto.o -o build/cryptotool.exe $(END) kuznechik-master/libkuznechik.a

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
