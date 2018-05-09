#pragma once

#include "Parameters.h"
#include "../cryptopp/osrng.h"
#include "../cryptopp/cryptlib.h"
#include "CipherUtils.h"
#include "HashBase.h"
#include "AsymmetricAuthenticationExtension.h"
#include <string>
#include <iostream>
#include <tuple>
#include <fstream>
#include <stdlib.h>  
#include <stdio.h>  


// This is done for convenience.
#define aes256 rijndael128_256
#define aes192 rijndael128_192
#define aes128 rijndael128_128



#ifdef _WIN32
    #include <direct.h>      
   #ifdef _WIN64
   #else
   #endif
#else 
    #include <sys/types.h> 
    #include <sys/stat.h> 
    #include <unistd.h>
    #include <sys/types.h>
    #include <pwd.h>
#endif

std::string DISCRETECRYPT_CONFIG();

void discrete_mkdir(const std::string& str);

std::string getScrypt(const std::string& password, const std::string& salt, int N = DISCRETECRYPT_DEFAULT_N, int p = DISCRETECRYPT_DEFAULT_P, int r = DISCRETECRYPT_DEFAULT_R, int len = DISCRETECRYPT_DEFAULT_LEN);

#if defined(_WIN32) || defined(_WIN64)
#else
int getch();
#endif

std::string getPassword();
CryptoPP::Integer stringToCryptoInt(const std::string& s);
std::string cryptoIntToString(const CryptoPP::Integer& n);
CryptoPP::Integer passwordToPrivate(const std::string& pass, const std::string& salt, const ScryptParameters& sp);

std::string intToScrypt(const CryptoPP::Integer& i, const ScryptParameters& sp, int keyLen, const FileProperties& fp);
CryptoPP::Integer createContact(Contact& con, const DHParameters& dh, const ScryptParameters& sp);
CryptoPP::Integer createContact(Contact& con, const DHParameters& dh, const ScryptParameters& sp, Contact* sender, std::string& password);


// This code will probably be replaced.
std::string getCipherName(CipherType p);

// This is somewhat of a factory design pattern.

void getEncryptor(CipherType p, Encryptor*& bc);
void getDecryptor(CipherType p, Encryptor*& bc);

void getHash(HashType h, Hash_Base*& bc);
void getHmac(HashType h, Hash_Base*& bc, const std::string& key);


std::string getHashName(HashType h);

int getHashOutputSize(HashType h);
int getHashBlockSize(HashType h);


int getCipherKeySize(CipherType p);

int getCipherBlockSize(CipherType p);

std::string to_hex(const std::string& str);
std::string to_hex(const char* str, int len);

template <class T>
void encodeFile(T& c, const std::string& fileName);

template <class T>
void decodeFile(T& c, const std::string& fileName);

bool checkFileExists(const std::string& name);

void decodeEncrypted(std::vector<Exchange>& exchanges, FileProperties& fp, const std::string& fileName);

std::string hashPad(std::string hash, int blockSize);

// Creates a key for the file.
void createFileKey(FileProperties& fp);


void hmacFile(const std::string& filename, const std::vector<DataExtension>& extensions, FileProperties& fp);

void bundleFile(const std::string& fileName, const std::string& outputFile, const Contact& sender, const std::string& password, HashType hashType);

AsymmetricAuthenticationSignature debundleFile(const std::string& fileName, const std::string& outputFile);
std::tuple<std::string, AsymmetricAuthenticationSignature> debundleFile(const std::string& fileName);

std::vector<Exchange> createExchanges(const std::vector<Contact>& recipients, FileProperties& fp,  std::string& password,  Contact* con = 0);

void encryptFile(const std::string& fileName, const std::string& outputFile, const std::vector<Exchange>& exchanges, const std::vector<DataExtension>& extensions, const FileProperties& fp, const std::string& password);
char decryptFile(const std::string& fileName, const std::string& outputFile, const std::vector<Exchange>& exchanges, std::vector<DataExtension>& extensions, const FileProperties& fp, const std::string& password, int person = 0);