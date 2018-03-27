#pragma once
#include "Parameters.h"
class AsymmetricAuthenticationExtension
{
    CryptoPP::Integer r, s;
    Contact _contact;
    private:
    std::string data;
    std::tuple<std::string, std::string> hashAndHmacFile(const std::string& file, const std::string& password, HashType ht);

    public:
    AsymmetricAuthenticationExtension();
    AsymmetricAuthenticationExtension(const DataExtension& d);
    AsymmetricAuthenticationExtension(const Contact& c, const std::string& file, const std::string& password, HashType ht);
    bool verify(std::string file, HashType ht);

    Contact contact() const;

    DataExtension out() const;
    void parse(const DataExtension& d);
};