#pragma once
#include "../cryptopp/integer.h"
#include <string>

#include <tuple>
#define DISCRETECRYPT_FILE_VERSION 3

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

    std::tuple<CryptoPP::Integer, CryptoPP::Integer> pohlig() const;
    

    // Currently a very dumb hack.
    std::string out() const;
};



// Octal Numbering System
// Typically will come in pairs of three.
// [Tier][Algorithm][Variant]
    
// Tier 0 are common standard algorithms. [AES, 3DES]
// Tier 1 are less common algorithms. [Threefish, Serpent, Twofish, Camellia]
// Tier 2-3 are algorithms that have country ties. [Kuzynechik, Aria, Kalyna, Simon/Speck]


// Name, ID, Cipher, Block Size, Key Size
#define CIPHER_ENUM(DO) \
    DO(AES128,          0000,   CryptoppEncryptor<CryptoPP::AES>,           128,    128) \
    DO(AES192,          0001,   CryptoppEncryptor<CryptoPP::AES>,           128,    192) \
    DO(AES256,          0002,   CryptoppEncryptor<CryptoPP::AES>,           128,    256) \
    DO(Threefish256,    0100,   CryptoppEncryptor<CryptoPP::Threefish256>,  256,    256) \
    DO(Threefish512,    0101,   CryptoppEncryptor<CryptoPP::Threefish512>,  512,    512) \
    DO(Threefish1024,   0102,   CryptoppEncryptor<CryptoPP::Threefish1024>, 1024,   1024) \
    DO(Camellia128,     0110,   CryptoppEncryptor<CryptoPP::Camellia>,      128,    128) \
    DO(Camellia192,     0111,   CryptoppEncryptor<CryptoPP::Camellia>,      128,    192) \
    DO(Camellia256,     0112,   CryptoppEncryptor<CryptoPP::Camellia>,      128,    256) \
    DO(Serpent128,      0120,   CryptoppEncryptor<CryptoPP::Serpent>,       128,    128) \
    DO(Serpent192,      0121,   CryptoppEncryptor<CryptoPP::Serpent>,       128,    192) \
    DO(Serpent256,      0122,   CryptoppEncryptor<CryptoPP::Serpent>,       128,    256) \
    DO(Twofish128,      0130,   CryptoppEncryptor<CryptoPP::Twofish>,       128,    128) \
    DO(Twofish192,      0131,   CryptoppEncryptor<CryptoPP::Twofish>,       128,    192) \
    DO(Twofish256,      0132,   CryptoppEncryptor<CryptoPP::Twofish>,       128,    256) \
    DO(Mars128,         0140,   CryptoppEncryptor<CryptoPP::MARS>,          128,    128) \
    DO(Mars160,         0141,   CryptoppEncryptor<CryptoPP::MARS>,          128,    160) \
    DO(Mars192,         0142,   CryptoppEncryptor<CryptoPP::MARS>,          128,    192) \
    DO(Mars224,         0143,   CryptoppEncryptor<CryptoPP::MARS>,          128,    224) \
    DO(Mars256,         0144,   CryptoppEncryptor<CryptoPP::MARS>,          128,    256) \
    DO(Mars384,         0145,   CryptoppEncryptor<CryptoPP::MARS>,          128,    384) \
    DO(Mars448,         0146,   CryptoppEncryptor<CryptoPP::MARS>,          128,    448) \
    DO(Cast6_128,       0150,   CryptoppEncryptor<CryptoPP::CAST256>,       128,    128) \
    DO(Cast6_160,       0151,   CryptoppEncryptor<CryptoPP::CAST256>,       128,    160) \
    DO(Cast6_192,       0152,   CryptoppEncryptor<CryptoPP::CAST256>,       128,    192) \
    DO(Cast6_224,       0153,   CryptoppEncryptor<CryptoPP::CAST256>,       128,    224) \
    DO(Cast6_256,       0154,   CryptoppEncryptor<CryptoPP::CAST256>,       128,    256) \
    DO(Kuznyechik,      0200,   KuznyechikEncryptor,                        128,    256) \
    DO(Aria128,         0210,   CryptoppEncryptor<CryptoPP::ARIA>,          128,    128) \
    DO(Aria192,         0211,   CryptoppEncryptor<CryptoPP::ARIA>,          128,    192) \
    DO(Aria256,         0212,   CryptoppEncryptor<CryptoPP::ARIA>,          128,    256) \
    DO(Speck128_128,    0220,   CryptoppEncryptor<CryptoPP::SPECK128>,      128,    128) \
    DO(Speck128_192,    0221,   CryptoppEncryptor<CryptoPP::SPECK128>,      128,    192) \
    DO(Speck128_256,    0222,   CryptoppEncryptor<CryptoPP::SPECK128>,      128,    256) \
    DO(Simon128_128,    0230,   CryptoppEncryptor<CryptoPP::SIMON128>,      128,    128) \
    DO(Simon128_192,    0231,   CryptoppEncryptor<CryptoPP::SIMON128>,      128,    192) \
    DO(Simon128_256,    0232,   CryptoppEncryptor<CryptoPP::SIMON128>,      128,    256) \
    DO(Kalyna128_128,   0240,   CryptoppEncryptor<CryptoPP::Kalyna128>,     128,    128) \
    DO(Kalyna128_256,   0241,   CryptoppEncryptor<CryptoPP::Kalyna128>,     128,    256) \
    DO(Kalyna256_256,   0242,   CryptoppEncryptor<CryptoPP::Kalyna256>,     256,    256) \
    DO(Kalyna256_512,   0243,   CryptoppEncryptor<CryptoPP::Kalyna256>,     256,    512) \
    DO(Kalyna512_512,   0244,   CryptoppEncryptor<CryptoPP::Kalyna512>,     512,    512) \
    DO(SM4,             0250,   CryptoppEncryptor<CryptoPP::SM4>,           128,    128) \


#define DO2(X, Y, Z, BLOCKSIZE, DO) \
    DO(X ## _224, Y ## 0, Z, 224, BLOCKSIZE) \
    DO(X ## _256, Y ## 1, Z, 256, BLOCKSIZE) \
    DO(X ## _384, Y ## 2, Z, 384, BLOCKSIZE) \
    DO(X ## _512, Y ## 3, Z, 512, BLOCKSIZE) \

#define DO3(X, Y, Z, BLOCKSIZE, DO) \
    DO2(X, Y, Z, BLOCKSIZE, DO) \
    DO(X ## _1024, Y ## 4, Z, 1024, BLOCKSIZE) \
       
/*
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
    DO(Kupyna256,           0210,       kupyna(256)) \
    DO(Kupyna512,           0211,       kupyna(512)) \
 */

#define HASH_ENUM(DO) \
    DO(SHA256,          0000,   CryptoppHash<CryptoPP::SHA256>,     256,    512) \
    DO(SHA384,          0001,   CryptoppHash<CryptoPP::SHA384>,     384,    1024) \
    DO(SHA512,          0002,   CryptoppHash<CryptoPP::SHA512>,     512,    1024) \
    DO(SHA3_224,        0010,   CryptoppHash<CryptoPP::SHA3_224>,   224,    1152) \
    DO(SHA3_256,        0011,   CryptoppHash<CryptoPP::SHA3_256>,   256,    1088) \
    DO(SHA3_384,        0012,   CryptoppHash<CryptoPP::SHA3_384>,   384,    832) \
    DO(SHA3_512,        0013,   CryptoppHash<CryptoPP::SHA3_512>,   512,    576) \
    DO3(SHAKE128,       002,    HashSqueeze<digestpp::shake128>,    1344,   DO) \
    DO3(SHAKE256,       003,    HashSqueeze<digestpp::shake256>,    1088,   DO) \
    DO3(Skein256,       010,    HashNormal<digestpp::skein256>,     256,    DO) \
    DO3(Skein512,       011,    HashNormal<digestpp::skein512>,     512,    DO) \
    DO3(Skein1024,      012,    HashNormal<digestpp::skein1024>,    1024,   DO) \
    DO(Whirlpool,       0130,   CryptoppHash<CryptoPP::Whirlpool>,  512,    512) \
    DO(Streebog256,     0200,   HashNormal2<digestpp::streebog>,    256,    512) \
    DO(Streebog512,     0201,   HashNormal2<digestpp::streebog>,    512,    512) \
    DO(Kupyna256,       0210,   HashNormal2<digestpp::kupyna>,      256,    512) \
    DO(Kupyna512,       0211,   HashNormal2<digestpp::kupyna>,      512,    1024) \


        
#define MAKE_STRING_ARRAY(VAR, VAL, CONS, OUTSIZE, BLOCKSIZE) #VAR,
#define MAKE_INT_ARRAY(VAR, VAL, CONS, OUTSIZE, BLOCKSIZE) VAL,
#define MAKE_ENUM(VAR, VAL, CONS, OUTSIZE, BLOCKSIZE) VAR = VAL,
#define MAKE_STRING(VAR, VAL, CONS, OUTSIZE, BLOCKSIZE) case VAR: return #VAR;
#define MAKE_CONS(VAR, VAL, CONS, OUTSIZE, BLOCKSIZE) case VAR: bc = new CONS(OUTSIZE); break;
#define MAKE_HMAC(VAR, VAL, CONS, OUTSIZE, BLOCKSIZE) case VAR: bc = new HMAC<CONS, BLOCKSIZE / 8>(key, OUTSIZE); break;
#define MAKE_OUTSIZE(VAR, VAL, CONS, OUTSIZE, BLOCKSIZE) case HashType::VAR: return OUTSIZE;
#define MAKE_BLOCKSIZE2(VAR, VAL, CONS, OUTSIZE, BLOCKSIZE) case HashType::VAR: return BLOCKSIZE;

#define MAKE_ENUM2(VAR, VAL, CONS, BLOCKSIZE, KEYSIZE) VAR = VAL,
#define MAKE_STRING_ARRAY2(VAR, VAL, CONS, BLOCKSIZE, KEYSIZE) #VAR,
#define MAKE_INT_ARRAY2(VAR, VAL, CONS, BLOCKSIZE, KEYSIZE) VAL,
#define MAKE_STRING2(VAR, VAL, CONS, BLOCKSIZE, KEYSIZE) case VAR: return #VAR;
#define MAKE_BLOCKSIZE(VAR, VAL, CONS, BLOCKSIZE, KEYSIZE) case CipherType::VAR: return BLOCKSIZE;
#define MAKE_KEYSIZE(VAR, VAL, CONS, BLOCKSIZE, KEYSIZE) case CipherType::VAR: return KEYSIZE;
#define MAKE_ENC(VAR, VAL, CONS, BLOCKSIZE, KEYSIZE) case CipherType::VAR: bc = new CONS; break; 
#define MAKE_DEC(VAR, VAL, CONS, BLOCKSIZE, KEYSIZE) case CipherType::VAR: bc = new CONS; break;


const int16_t AVAILABLE_CIPHERS_CODES[] = {
    CIPHER_ENUM(MAKE_INT_ARRAY2)
};

const char* const AVAILABLE_CIPHERS[] = {
    CIPHER_ENUM(MAKE_STRING_ARRAY2)
};

const int16_t AVAILABLE_HASHES_CODES[] = {
    HASH_ENUM(MAKE_INT_ARRAY)
};

const char* const AVAILABLE_HASHES[] = {
    HASH_ENUM(MAKE_STRING_ARRAY)
};

enum ExtensionType : uint8_t
{
    CUSTOM,
    SYMMETRIC,
    ASYMMETRIC, 
    MESSAGE,
    AUTHORIZATION
};

enum CipherType : int16_t
{
    CIPHER_ENUM(MAKE_ENUM2)               
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
    std::string uid(HashType ht = HashType::SHA256) const;
    std::string uidHex(HashType ht = HashType::SHA256) const;
    bool verify(std::string pass) const;
};


// This goes at the beginning of every encrypted file.
struct FileProperties
{
    char version = DISCRETECRYPT_FILE_VERSION;
    int16_t recipients = 1;
    int16_t extensions = 0;
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
    
    CryptoPP::Integer computed;

    Exchange();
    Exchange(const Exchange& ex);
    Exchange(const PersonParameters& a, const PersonParameters& b, const ScryptParameters& s, const CipherParams& cp, const DHParameters& dh);

    Exchange(const std::string& in, int offset = 0);
    void parse(const std::string& in, int offset = 0);

    Contact aliceContact() const;
    Contact bobContact() const;

    std::string out() const;
};


struct DataExtension 
{
    ExtensionType et = CUSTOM;
    std::string data = "";
    std::string out() const;
    void parse(const std::string& in, int offset = 0);
};