#pragma once
#include "HashBase.h"

template<class T>
class CryptoppHash : public Hash_Base
{
    private:
    T* algo;
    public:
    CryptoppHash() : algo(new T)
    {

    }

    CryptoppHash(int size) : algo(new T)
    {

    }

    ~CryptoppHash()
    {
        delete algo;
    }

    void absorb(const unsigned char* buf, int len) override
    {
        algo->Update(buf, len);
    }

    void digest(unsigned char* buf, int len) override
    {
        algo->Final(buf);
    }

    std::string hexdigest() override
    {
        // Needs implementation.
        return "";
    }
};
