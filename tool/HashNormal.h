#pragma once
#include "HashBase.h"
template <class T> class HashNormal : public Hash_Base
{
    private:
    T* hashFunc;
    public:


    HashNormal() : hashFunc(new T())
    {

    }

    HashNormal(int size) : hashFunc(new T(size))
    {
    
    }

    ~HashNormal()
    {
        delete hashFunc;
    }

    void absorb(const unsigned char* buf, int len) override
    {
        hashFunc->absorb(buf, len);    
    }

    void digest(unsigned char* buf, int len) override
    {
        hashFunc->digest(buf, len);    
    }

    std::string hexdigest() override
    {
        return hashFunc->hexdigest();
    }
};

// For Kupyna, might refactor out.
template <class T> class HashNormal2 : public Hash_Base
{
    private:
    T* hashFunc;
    public:

    HashNormal2()
    {

    }

    HashNormal2(int size) : hashFunc(new T(size))
    {
    
    }

    ~HashNormal2()
    {
        delete hashFunc;
    }

    void absorb(const unsigned char* buf, int len) override
    {
        hashFunc->absorb(buf, len);    
    }

    void digest(unsigned char* buf, int len) override
    {
        hashFunc->digest(buf, len);    
    }

    std::string hexdigest() override
    {
        return hashFunc->hexdigest();
    }
};
