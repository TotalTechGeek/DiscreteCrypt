#pragma once
#include "../cryptopp/integer.h"
#include <string>

using namespace CryptoPP;
class DHParameters
{
    private:
    Integer modulus;
    Integer generator;

    public:
    DHParameters() : modulus("0"), generator("0")
    {

    }

    DHParameters(const DHParameters& d) : modulus(d.modulus), generator(d.generator)
    {

    }

    DHParameters(const std::string& in, int offset = 0) : modulus("0"), generator("0")
    {
        parse(in, offset);
    }

    DHParameters(const char* gen, const char* mod) : modulus(mod), generator(gen)
    {}

    DHParameters(const std::string& gen, const std::string& mod) : modulus(mod.c_str()), generator(gen.c_str())
    {}

    void parse(const std::string& in, int offset = 0)
    {
        int16_t len1, len2;

        len1 = *(int16_t*)&in[offset];
        len2 = *(int16_t*)&in[offset + sizeof(int16_t)];
        
        modulus.Decode((unsigned char*)&in[offset + 2 * sizeof(int16_t)], len1);
        generator.Decode((unsigned char*)&in[offset + 2 * sizeof(int16_t) + len1], len2);
    }

    int len() const
    {
        return modulus.ByteCount() + generator.ByteCount() + sizeof(int16_t) * 2;
    }

    Integer mod() const
    {
        return modulus;
    }

    void mod(Integer x)
    {
        modulus = x;
    }

    Integer gen() const
    {
        return generator;
    }

    void gen(Integer x)
    {
        generator = x;
    }

    // Currently a very dumb hack.
    std::string out() const
    {
        unsigned char* out1 = new unsigned char[modulus.ByteCount()];
        unsigned char* out2 = new unsigned char[generator.ByteCount()];
        std::string result;
        
        //append the lengths
        int16_t len1 = (int16_t)modulus.ByteCount(), len2 = (int16_t)generator.ByteCount();
        result.append((char*)(&len1), sizeof(int16_t));
        result.append((char*)(&len2), sizeof(int16_t));

        modulus.Encode(out1, modulus.ByteCount());
        result.append((char*)out1, modulus.ByteCount());
        
        generator.Encode(out2, generator.ByteCount());
        result.append((char*)out2, generator.ByteCount());
        
        delete[] out1;
        delete[] out2;

        return result;
    }
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

enum CipherType : int16_t
{
    CIPHER_ENUM(MAKE_ENUM)               
};

struct CryptoParams
{
    CipherType cipherType;
    int8_t mode;

    CryptoParams() : cipherType(AES256), mode()
    {

    }

    CryptoParams(const CryptoParams& c) : cipherType(c.cipherType), mode(c.mode)
    {

    }
};

// Fortunately the same size each time :)
struct ScryptParameters
{
    int32_t N;
    int32_t P;
    int32_t R;
    int32_t len;

    ScryptParameters() : N(1 << 14), P(16), R(8), len(32)
    {

    }

    ScryptParameters(const ScryptParameters& s) : N(s.N), P(s.P), R(s.R), len(s.len)
    {

    }

    ScryptParameters(int32_t N, int32_t P, int32_t R, int32_t len) : N(N), P(P), R(R), len(len)
    {

    }

    // This is a prewritten snippet of code in case compilers
    // are somehow allowed to reorder members.
    /*
    void parse(const std::string& in, int offset = 0)
    {
        N =     (int32_t)&in[offset + 0*sizeof(int32_t)];
        P =     (int32_t)&in[offset + 1*sizeof(int32_t)];
        R =     (int32_t)&in[offset + 2*sizeof(int32_t)];
        len =   (int32_t)&in[offset + 3*sizeof(int32_t)];
    }

    std::string out() const
    {
        std::string result;

        result.append((char*)&N, sizeof(int32_t));
        result.append((char*)&P, sizeof(int32_t));
        result.append((char*)&R, sizeof(int32_t));
        result.append((char*)&len, sizeof(int32_t));
        
        return result;
    }*/

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
    Integer publicKey;

    PersonParameters()
    {

    }

    PersonParameters(const PersonParameters& p) : identity(p.identity), salt(p.salt), publicKey(p.publicKey)
    {

    }

    PersonParameters(const std::string& identity, const std::string& salt, char* publicKey) : identity(identity), salt(salt), publicKey(publicKey)
    {

    }

    PersonParameters(const std::string& identity, const std::string& salt, Integer publicKey) : identity(identity), salt(salt), publicKey(publicKey)
    {

    }

    PersonParameters(const std::string& in, int offset = 0) : publicKey("0")
    {
        parse(in, offset);
    }

    void parse(const std::string& in, int offset = 0)
    {
        int16_t len1, len2, len3;

        len1 = *(int16_t*)&in[offset + 0*sizeof(int16_t)];
        len2 = *(int16_t*)&in[offset + 1*sizeof(int16_t)];
        len3 = *(int16_t*)&in[offset + 2*sizeof(int16_t)];

        identity = in.substr(offset + 3*sizeof(int16_t), len1);
        salt = in.substr(offset + 3*sizeof(int16_t) + len1, len2);
        publicKey.Decode((unsigned char*)&in[offset + 3*sizeof(int16_t) + len1 + len2], len3);
    }

    int len() const
    {
        return salt.length() + identity.length() + publicKey.ByteCount() + sizeof(int16_t) * 3;
    }

    std::string saltHex() const
    {
        std::string result;
        static char lookup[] = "0123456789ABCDEF";
        for(int i = 0; i < salt.length(); i++)
        {
            result += lookup[(salt[i] >> 4) & 15];
            result += lookup[salt[i] & 15];
        }

        return result;
    }

    std::string out() const
    {
        std::string result;

        int16_t len = identity.length();
        result.append((char*)&len, sizeof(int16_t));

        len = salt.length();
        result.append((char*)&len, sizeof(int16_t));
                
        len = (int16_t)publicKey.ByteCount();
        result.append((char*)&len, sizeof(int16_t));
        
        unsigned char* out1 = new unsigned char[len];
        publicKey.Encode(out1, len);
        
        result.append(identity);
        result.append(salt);
        result.append((char*)out1, len);

        delete[] out1;

        return result;
    }

};

struct Contact
{
    PersonParameters person;
    ScryptParameters sp;
    DHParameters dh;

    Contact()
    {

    }

    Contact(const Contact& c) : person(c.person), sp(c.sp), dh(c.dh)
    {

    }

    Contact(const PersonParameters& p, const ScryptParameters& sp, const DHParameters& dh) : dh(dh), sp(sp), person(person)
    {
    }

    Contact(const std::string& in, int offset = 0) 
    {
        parse(in, offset);
    }

    void parse(const std::string& in, int offset = 0)
    {
        person.parse(in, offset);
        sp = *(ScryptParameters*)&in[offset + person.len()];
        dh.parse(in, sizeof(ScryptParameters) + offset + person.len());
    }

    std::string out() const
    {
        std::string result;

        result.append(person.out());
        result.append((char*)&sp, sizeof(sp));
        result.append(dh.out());

        return result;
    }
};


// This is gonna be a pain lol.
struct Exchange
{
    PersonParameters alice, bob;
    ScryptParameters sp;
    CryptoParams cp;
    DHParameters dh;

    Exchange()
    {}

    Exchange(const Exchange& ex) : alice(ex.alice), bob(ex.bob), sp(ex.sp), cp(ex.cp), dh(ex.dh)
    {

    }

    Exchange(const PersonParameters& a, const PersonParameters& b, const ScryptParameters& s, const CryptoParams& cp, const DHParameters& dh) : alice(a), bob(b), sp(s), dh(dh), cp(cp)
    {

    }

    // Such a hack, let us hope it works. :D
    Exchange(const std::string& in, int offset = 0) 
    {
        parse(in, offset);
    }

    void parse(const std::string& in, int offset = 0)
    {
        alice.parse(in, offset);
        bob.parse(in, alice.len() + offset);
        sp = *(ScryptParameters*)&in[offset + alice.len() + bob.len()];
        cp = *(CryptoParams*)&in[offset + alice.len() + bob.len() + sizeof(ScryptParameters)];
        dh.parse(in, sizeof(ScryptParameters) + offset + alice.len() + bob.len() + sizeof(CryptoParams));
    }

    std::string out() const
    {
        std::string result;

        result.append(alice.out());
        result.append(bob.out());
        result.append((char*)&sp, sizeof(ScryptParameters));
        result.append((char*)&cp, sizeof(CryptoParams));
        result.append(dh.out());

        return result;
    }
};

