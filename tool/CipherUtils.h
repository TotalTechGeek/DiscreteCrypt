#pragma once
class Encryptor
{
    public:
    virtual void setKeyWithIV(const unsigned char* key, int keysize, const unsigned char* iv, int blocksize) = 0;
    virtual void process(const unsigned char* in, unsigned char* out, int len) = 0; 
};

