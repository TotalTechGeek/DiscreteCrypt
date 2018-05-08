#pragma once
#include <string>
#include "../digestpp-master/digestpp.hpp"
#include "../cppcrypto/cppcrypto/cppcrypto.h"



class Hash_Base
{
    public:
    virtual void absorb(const unsigned char* buf, int len) = 0;
    virtual void digest(unsigned char* buf, int len) = 0;
    virtual std::string hexdigest() = 0;
};
