#pragma once
#include "HashBase.h"

template<class T, int block_size>
class HMAC : public Hash_Base
{
    private:
    T *x, *y;
    std::string key, key2;
    int size;
    void keyFix()
    {
        if(key.length() > block_size)
        {
            T *hashKey;
            if(size)
            {
                hashKey = new T(size);
            }
            else
            {
                hashKey = new T;
            }

            hashKey->absorb((unsigned char*)&key[0], key.length());
            hashKey->digest((unsigned char*)&key[0], block_size);
            delete hashKey;
        }
    
        while(key.length() < block_size)
        {
            key += '\0';
        }

        key2 = key;

        for(int i = 0; i < block_size; i++)
        {
            key[i] ^= 0x36; //ikey
            key2[i] ^= 0x5c; //okey
        }
    }

    HMAC(const HMAC&);

    public:
    HMAC(const std::string& key) : key(key), x(new T()), y(new T()), size(0)
    {
        keyFix();
        x->absorb((unsigned char*)&this->key[0], block_size);
        y->absorb((unsigned char*)&this->key2[0], block_size);
    }

    HMAC(const std::string& key, int size) : key(key), x(new T(size)), y(new T(size)), size(size)
    {
        keyFix();
        x->absorb((unsigned char*)&this->key[0], block_size);
        y->absorb((unsigned char*)&this->key2[0], block_size);
    }

    ~HMAC()
    {
        delete x;
        delete y;
    }


    void absorb(const unsigned char* buf, int len) override
    {
        x->absorb(buf, len);
    }

    void digest(unsigned char* buf, int len) override
    {
        unsigned char* buf2 = new unsigned char[len];
        x->digest(buf, len);
        y->absorb(buf, len);
        y->digest(buf, len);
    }

    std::string hexdigest() override
    {
        return "";
    }
};
