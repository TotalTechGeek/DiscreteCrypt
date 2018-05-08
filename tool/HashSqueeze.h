#pragma once
#include "HashBase.h"
#include <cassert>
template <class T> class HashSqueeze : public Hash_Base
{
    private:
    T* hashFunc;
    int size; 
    public:

    HashSqueeze() : size(256 / 8), hashFunc(new T())
    {

    }

    HashSqueeze(int size) : size(size / 8), hashFunc(new T())
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
        unsigned char *buf2 = new unsigned char[len * 8]();
        assert(len >= size);
        hashFunc->squeeze(buf2, size);
        memcpy(buf, buf2, size);
        delete[] buf2;
    }

    std::string hexdigest() override
    {
        return hashFunc->hexsqueeze(size);
    }
};
