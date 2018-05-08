#include "SymmetricAuthenticationExtension.h"
#include "toolCrypto.h"

SymmetricAuthenticationExtension::SymmetricAuthenticationExtension() : _prompt(""), data("")
{
}

SymmetricAuthenticationExtension::SymmetricAuthenticationExtension(std::string prompt, std::string pass, std::string file, HashType ht) : _prompt(prompt), data("")
{
    data = hmacFile(file, pass, ht);
}

SymmetricAuthenticationExtension::SymmetricAuthenticationExtension(const DataExtension& d) : _prompt(""), data("")
{   
    parse(d);
}

std::string SymmetricAuthenticationExtension::prompt() const
{
    return _prompt;
}

DataExtension SymmetricAuthenticationExtension::out() const
{
    DataExtension de;
    de.et = ExtensionType::SYMMETRIC;

    int16_t len = _prompt.size();
    de.data.append((char*)&len, sizeof(int16_t));
    de.data.append(_prompt);

    len = data.size();

    de.data.append((char*)&len, sizeof(int16_t));
    de.data.append(data);

    return de;
}

bool SymmetricAuthenticationExtension::check(std::string pass, std::string file, HashType ht) const
{
    using namespace std;
    std::string str = hmacFile(file, pass, ht);
    return str == this->data;
}

std::string SymmetricAuthenticationExtension::hmacFile(const std::string& filename, const std::string& pass, HashType ht) const
{
    using namespace std;
    unsigned char* hash;
    Hash_Base* mac;
    getHmac(ht, mac, pass);
    
    ifstream fi(filename, ios::binary);
    hash = new unsigned char[getHashOutputSize(ht) / 8]();
    int x = getHashBlockSize(ht) / 8;
    if(x == 0) x = getHashOutputSize(ht) / 8;
    char* block = new char[x]();
    if(fi.good())
    {
        // Gets the file size (hopefully)
        int fsize = 0;
        fi.seekg(0, ios::end);
        fsize = (int)fi.tellg() - fsize;
        fi.seekg(0, ios::beg);
        while(fsize > x)
        {
            fi.read(block, x);
            mac->absorb((unsigned char*)block, x);
            fsize -= x;
        }
        if(fsize)
        {
            fi.read(block, fsize);
            mac->absorb((unsigned char*)block, fsize);
        }
        mac->digest(hash, getHashOutputSize(ht) / 8);
    }
    string res("");
    res.append((char*)hash, getHashOutputSize(ht) / 8);
    
    fi.close();
    delete[] block;
    delete[] hash;
    delete mac;   
    return res;
}

void SymmetricAuthenticationExtension::parse(const DataExtension& d)
{
    using namespace std;
    int offset = 0;
    int16_t len = *(int16_t*)&d.data[offset];
    offset += sizeof(int16_t);
   
    _prompt = d.data.substr(offset, len);
    offset += len;
    
    len = *(int16_t*)&d.data[offset];
    
    offset += sizeof(int16_t);
    data = d.data.substr(offset, len);
}