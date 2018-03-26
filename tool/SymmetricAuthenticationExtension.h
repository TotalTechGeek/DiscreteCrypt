#pragma once 
#include "Parameters.h"

class SymmetricAuthenticationExtension
{
    std::string _prompt;
    std::string data;

    std::string hmacFile(const std::string& filename, const std::string& pass, HashType ht) const;

    public:
    
    SymmetricAuthenticationExtension();
    SymmetricAuthenticationExtension(std::string prompt, std::string pass, std::string file, HashType ht);
    SymmetricAuthenticationExtension(const DataExtension& d);

    DataExtension out() const;

    std::string prompt() const;
    void parse(const DataExtension& d);
    bool check(std::string pass, std::string file, HashType ht) const;
};