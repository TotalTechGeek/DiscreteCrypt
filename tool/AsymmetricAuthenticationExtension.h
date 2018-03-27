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

    DataExtension outData() const;
    std::string out() const;
    
    void parse(const std::string& data, int offset = 0);
    void parse(const DataExtension& d);
};

// Simple Adapter Pattern. Aggregation made more sense here.
class AsymmetricAuthenticationSignature
{
    private:
    AsymmetricAuthenticationExtension aae;
    HashType ht;
    public:
    AsymmetricAuthenticationSignature();
    AsymmetricAuthenticationSignature(const Contact& c, const std::string& file, const std::string& password, HashType ht);
    
    bool verify(std::string file);

    std::string out() const;
    void parse(const std::string& data, int offset = 0);
};