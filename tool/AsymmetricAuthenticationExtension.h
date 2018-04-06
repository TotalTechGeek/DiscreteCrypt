#pragma once
#include "Parameters.h"
class AsymmetricAuthenticationExtension
{
    private:
    std::tuple<std::string, std::string> hashAndHmacFile(const std::string& file, const std::string& password, HashType ht);
    std::tuple<std::string, std::string> hashAndHmacData(const std::string& file, const std::string& password, HashType ht);
    
    CryptoPP::Integer r, s;
    Contact _contact;

    public:
    AsymmetricAuthenticationExtension();
    AsymmetricAuthenticationExtension(const DataExtension& d);
    AsymmetricAuthenticationExtension(const Contact& c, const std::string& file, const std::string& password, HashType ht, bool data = false);
    bool verify(std::string file, HashType ht, bool data = false);

    

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
    AsymmetricAuthenticationSignature(const Contact& c, const std::string& file, const std::string& password, HashType ht, bool data = false);
    
    bool verify(std::string file, bool data = false);

    Contact contact() const;

    HashType hashType() const;

    std::string out() const;
    void parse(const std::string& data, int offset = 0);
};