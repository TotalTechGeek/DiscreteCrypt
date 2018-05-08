#pragma once
#include "CipherUtils.h"
#include "../kuznechik/kuzcipher.h"

class KuznyechikEncryptor : public Encryptor
{
    private:
    KuzCtr* encryptor; 
    public:
    KuznyechikEncryptor() : encryptor(new KuzCtr()) 
    {

    }

    ~KuznyechikEncryptor() 
    {
        delete encryptor;
    }

    void setKeyWithIV(const unsigned char* key, int keysize, const unsigned char* iv, int blocksize) override
    {
        encryptor->setKey(key, keysize);
        encryptor->setIV(iv, blocksize);
    }

    void process(const unsigned char* in, unsigned char* out, int len) override
    {
        encryptor->encrypt(in, out, len);
    } 

};