#pragma once
#include "../cryptopp/integer.h"
#include <string>

class DHParameters
{
    private:
    CryptoPP::Integer modulus;
    CryptoPP::Integer generator;

    public:
    DHParameters();
    DHParameters(const DHParameters& d);
    DHParameters(const std::string& in, int offset = 0);
    DHParameters(const char* gen, const char* mod);
    DHParameters(const std::string& gen, const std::string& mod);
    void parse(const std::string& in, int offset = 0);

    int len() const;
    CryptoPP::Integer mod() const;
    void mod(CryptoPP::Integer x);
    CryptoPP::Integer gen() const;
    void gen(CryptoPP::Integer x);

    // Currently a very dumb hack.
    std::string out() const;
};



// Octal Numbering System
// Typically will come in pairs of three.
// [Tier][Algorithm][Variant]
    
// Tier 0 are common standard algorithms. [AES, 3DES]
// Tier 1 are less common algorithms. [Threefish, Serpent, Twofish, Camellia]
// Tier 2-3 are algorithms that have country ties. [Kuzynechik, Aria, Kalyna, Simon/Speck]

#define CIPHER_ENUM(DO) \
    DO(AES128,          0000,   aes128) \
    DO(AES192,          0001,   aes192) \
    DO(AES256,          0002,   aes256) \
    DO(Threefish256,    0100,   threefish256_256) \
    DO(Threefish512,    0101,   threefish512_512) \
    DO(Threefish1024,   0102,   threefish1024_1024) \
    DO(Camellia128,     0110,   camellia128) \
    DO(Camellia192,     0111,   camellia192) \
    DO(Camellia256,     0112,   camellia256) \
    DO(Serpent128,      0120,   serpent128) \
    DO(Serpent192,      0121,   serpent192) \
    DO(Serpent256,      0122,   serpent256) \
    DO(Twofish128,      0130,   twofish128) \
    DO(Twofish192,      0131,   twofish192) \
    DO(Twofish256,      0132,   twofish256) \
    DO(Kuznyechik,      0200,   kuznyechik) \
    DO(Aria128,         0210,   aria128) \
    DO(Aria192,         0211,   aria192) \
    DO(Aria256,         0212,   aria256) \
    DO(Speck128_128,    0220,   speck128_128) \
    DO(Speck128_192,    0221,   speck128_192) \
    DO(Speck128_256,    0222,   speck128_256) \
    DO(Simon128_128,    0230,   simon128_128) \
    DO(Simon128_192,    0231,   simon128_192) \
    DO(Simon128_256,    0232,   simon128_256) \
    DO(Kalyna128_128,   0240,   kalyna128_128) \
    DO(Kalyna128_256,   0241,   kalyna128_256) \
    DO(Kalyna256_256,   0242,   kalyna256_256) \
    DO(Kalyna256_512,   0243,   kalyna256_512) \
    DO(Kalyna512_512,   0244,   kalyna512_512) 

#define DO2(X, Y, Z, DO) \
    DO(X ## _224, Y ## 0, Z(224)) \
    DO(X ## _256, Y ## 1, Z(256)) \
    DO(X ## _384, Y ## 2, Z(384)) \
    DO(X ## _512, Y ## 3, Z(512)) \

#define DO3(X, Y, Z, DO) \
    DO2(X, Y, Z, DO) \
    DO(X ## _1024, Y ## 4, Z(1024)) \
       
#define HASH_ENUM(DO) \
    DO(SHA256,              0000,       sha256) \
    DO(SHA384,              0001,       sha384) \
    DO(SHA512,              0002,       sha512) \
    DO2(SHA3,               001,       sha3, DO) \
    DO3(SHAKE128,           002,       shake128, DO) \
    DO3(SHAKE256,           003,       shake256, DO) \
    DO3(Skein256,           010,       skein256, DO) \
    DO3(Skein512,           011,       skein512, DO) \
    DO3(Skein1024,          012,       skein1024, DO) \
    DO(Whirlpool,           0130,       whirlpool) \
    DO(Streebog256,         0200,       streebog(256)) \
    DO(Streebog512,         0201,       streebog(512)) \
    DO2(Kupyna,             021,       kupyna, DO) \
        
#define MAKE_STRING_ARRAY(VAR, VAL, CONS) #VAR,
#define MAKE_INT_ARRAY(VAR, VAL, CONS) VAL,
#define MAKE_ENUM(VAR, VAL, CONS) VAR = VAL,
#define MAKE_STRING(VAR, VAL, CONS) case VAR: return #VAR;
#define MAKE_CONS(VAR, VAL, CONS) case VAR: bc = new CONS; break;

const int16_t AVAILABLE_CIPHERS_CODES[] = {
    CIPHER_ENUM(MAKE_INT_ARRAY)
};

const char* const AVAILABLE_CIPHERS[] = {
    CIPHER_ENUM(MAKE_STRING_ARRAY)
};

const int16_t AVAILABLE_HASHES_CODES[] = {
    HASH_ENUM(MAKE_INT_ARRAY)
};

const char* const AVAILABLE_HASHES[] = {
    HASH_ENUM(MAKE_STRING_ARRAY)
};

enum CipherType : int16_t
{
    CIPHER_ENUM(MAKE_ENUM)               
};

enum HashType: int16_t
{
    HASH_ENUM(MAKE_ENUM)
};

struct CipherParams
{
    CipherType cipherType;
    int8_t mode;

    CipherParams();
    CipherParams(const CipherParams& c);
};

// Fortunately the same size each time :)
struct ScryptParameters
{
    int32_t N;
    int32_t P;
    int32_t R;
    int32_t len;

    ScryptParameters();
    ScryptParameters(const ScryptParameters& s);
    ScryptParameters(int32_t N, int32_t P, int32_t R, int32_t len);
};

// This will also be paired with a set of dh params and a scrypt.
struct PersonParameters
{
    // This can be optionally blank.
    std::string identity; 

    // This is used for the Scrypt. 
    std::string salt;

    // This is the person's public key.
    // Ideally this would be in contact but meh
    CryptoPP::Integer publicKey;

    PersonParameters();
    PersonParameters(const PersonParameters& p);
    PersonParameters(const std::string& identity, const std::string& salt, char* publicKey);
    PersonParameters(const std::string& identity, const std::string& salt, CryptoPP::Integer publicKey);
    PersonParameters(const std::string& in, int offset = 0);

    void parse(const std::string& in, int offset = 0);

    int len() const;
    std::string saltHex() const;
    
    std::string out() const;
};

struct Contact
{
    PersonParameters person;
    ScryptParameters sp;
    DHParameters dh;

    Contact();
    Contact(const Contact& c);
    Contact(const PersonParameters& p, const ScryptParameters& sp, const DHParameters& dh);
    Contact(const std::string& in, int offset = 0);
    void parse(const std::string& in, int offset = 0);
    std::string out() const;
};


// This goes at the beginning of every encrypted file.
struct FileProperties
{
    char version = 1;
    int16_t recipients = 1;
    CipherParams cp;
    HashType ht;
    std::string hash;
    std::string key;

    FileProperties(CipherParams cp, HashType ht);

    // simple parsing.
    void parse(const std::string& in, int offset = 0);
    std::string out() const;
};

// This is gonna be a pain lol.
struct Exchange
{
    PersonParameters alice, bob;
    ScryptParameters sp;
    DHParameters dh;

    Exchange();
    Exchange(const Exchange& ex);
    Exchange(const PersonParameters& a, const PersonParameters& b, const ScryptParameters& s, const CipherParams& cp, const DHParameters& dh);

    Exchange(const std::string& in, int offset = 0);
    void parse(const std::string& in, int offset = 0);

    std::string out() const;
};

