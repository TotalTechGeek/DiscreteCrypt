#pragma once
#include "HashBase.h"
template <class T> class HashSqueeze : public Hash_Base
{
    private:
    T* hashFunc;
    int size; 
    public:

    HashSqueeze(int size) : size(size), hashFunc(new T())
    {

    }

    ~HashSqueeze()
    {
        delete hashFunc;
    }


    void absorb(const unsigned char* buf, int len) override
    {
        hashFunc->absorb(buf, len);    
    }

    void digest(unsigned char* buf, int len) override
    {
        assert(len >= size / 8);

        hashFunc->squeeze(buf, size);    
    }

    std::string hexdigest() override
    {
        return hashFunc->hexsqueeze(size);
    }
};
