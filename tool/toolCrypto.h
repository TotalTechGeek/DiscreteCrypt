#pragma once

#include "Parameters.h"
#include "../cryptopp/osrng.h"
#include "../cppcrypto/cppcrypto/cppcrypto.h"
#include <string>
#include <iostream>
#include <fstream>

// This is done for convenience.
#define aes256 rijndael128_256
#define aes192 rijndael128_192
#define aes128 rijndael128_128

std::string getScrypt(const std::string& password, const std::string& salt, int N = 1 << 14, int p = 16, int r = 8, int len = 32);

#if defined(_WIN32) || defined(_WIN64)
#include <conio.h>
#include <stdio.h>
#include <io.h>

// Works on Windows with Mingw32_64
std::string getPassword();
#else
int getch();
std::string getPassword();
#endif


std::string intToScrypt(const CryptoPP::Integer& i, const ScryptParameters& sp, int keyLen, const FileProperties& fp);
CryptoPP::Integer createContact(Contact& con, const DHParameters& dh, const ScryptParameters& sp);
CryptoPP::Integer createContact(Contact& con, const DHParameters& dh, const ScryptParameters& sp, const std::string& identity, std::string& password);


// This code will probably be replaced.
std::string getCipherName(CipherType p);

// This is somewhat of a factory design pattern.
void getCipher(CipherType p, cppcrypto::block_cipher*& bc);
void getHash(HashType h, cppcrypto::crypto_hash*& bc);


std::string getHashName(HashType h);

int getHashOutputSize(HashType h);

int getCipherKeySize(CipherType p);

int getCipherBlockSize(CipherType p);

template <class T>
void encodeFile(T& c, const std::string& fileName);


template <class T>
void decodeFile(T& c, const std::string& fileName);


void decodeEncrypted(std::vector<Exchange>& exchanges, FileProperties& fp, const std::string& fileName);

std::string hashPad(std::string hash, int blockSize);

// Creates a key for the file.
void createFileKey(FileProperties& fp);

// Todo: Create a new method to compute a hash of the file for the extensions.
// Since extensions will be included in the encrypted payload, HMACs will not be necessary
// even if there were a way to extract a hash from a signature.

void hmacFile(const std::string& filename, const std::vector<DataExtension>& extensions, FileProperties& fp);

// The functionality is thought out, it's just not properly implemented.
// The good news is that this is supported now, which means that when the behavior is implemented, 
// older versions won't be negatively affected by its addition.
DataExtension symmetricSign(const FileProperties& fp, const std::string& password);

void encryptFile(const std::string& fileName, const std::string& outputFile, const std::vector<Contact>& recipients, const std::vector<DataExtension>& extensions, const FileProperties& fp, std::string& password);
char decryptFile(const std::string& fileName, const std::string& outputFile, const std::vector<Exchange>& exchanges, std::vector<DataExtension>& extensions, const FileProperties& fp, const std::string& password, int person = 0);