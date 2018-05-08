#pragma once
#include "CipherUtils.h"

#include "../cryptopp/aes.h"
#include "../cryptopp/threefish.h"
#include "../cryptopp/twofish.h"
#include "../cryptopp/camellia.h"
#include "../cryptopp/serpent.h"
#include "../cryptopp/cast.h"
#include "../cryptopp/mars.h"
#include "../cryptopp/simon.h"
#include "../cryptopp/speck.h"
#include "../cryptopp/aria.h"
#include "../cryptopp/kalyna.h"
#include "../cryptopp/sm4.h"

#include "../cryptopp/modes.h"

template<class T>
class CryptoppEncryptor : public Encryptor
{
    private:
    typename CryptoPP::CTR_Mode<T>::Encryption* encryptor;
    public:
    CryptoppEncryptor() : encryptor(new typename CryptoPP::CTR_Mode<T>::Encryption)
    {
    }

    ~CryptoppEncryptor()
    {
        delete encryptor;
    }

    void setKeyWithIV(const unsigned char* key, int keysize, const unsigned char* iv, int blocksize) override
    {
        encryptor->SetKeyWithIV(key, keysize, iv, blocksize);
    }

    void process(const unsigned char* in, unsigned char* out, int len) override
    {
        encryptor->ProcessData(out, in, len);
    } 
};