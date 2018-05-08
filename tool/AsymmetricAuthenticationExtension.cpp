#include "AsymmetricAuthenticationExtension.h"
#include "toolCrypto.h"

using CryptoPP::Integer;


AsymmetricAuthenticationExtension::AsymmetricAuthenticationExtension() : r("0"), s("0"), _contact()
{
}

AsymmetricAuthenticationExtension::AsymmetricAuthenticationExtension(const DataExtension& d) : r("0"), s("0"), _contact()
{
    parse(d);
}

AsymmetricAuthenticationExtension::AsymmetricAuthenticationExtension(const Contact& c, const std::string& file, const std::string& password, HashType ht, bool data) : r("0"), s("0"), _contact(c)
{
    using namespace std;
    Integer pohlig, factors;
    tie(pohlig, factors) = _contact.dh.pohlig();    
    
    // This converts the public key to its proper DSA public key.
    Integer g = a_exp_b_mod_c(_contact.dh.gen(), factors, _contact.dh.mod());
    
    string hash, hmac;
    if(data)
    {
        tie(hash, hmac) = hashAndHmacData(file, password, ht);
    }
    else
    {
        tie(hash, hmac) = hashAndHmacFile(file, password, ht);
    }
    
    Integer x = passwordToPrivate(password, _contact.person.salt, _contact.sp);
    Integer k = stringToCryptoInt(hmac), H = stringToCryptoInt(hash);
    
    r = a_exp_b_mod_c(g, k, _contact.dh.mod()) % pohlig;
    s = (k.InverseMod(pohlig) * (H + x*r)) % pohlig;
}


bool AsymmetricAuthenticationExtension::verify(std::string file, HashType ht, bool data)
{
    using namespace std;
    if(r != 0 && s != 0)
    {
        Integer pohlig, factors;
        tie(pohlig, factors) = _contact.dh.pohlig();    
        
        // This converts the public key to its proper DSA public key.
        Integer pub2 = a_exp_b_mod_c(_contact.person.publicKey, factors, _contact.dh.mod());
        Integer g = a_exp_b_mod_c(_contact.dh.gen(), factors, _contact.dh.mod());

        string hash, hmac;

        if(data)
        {
            tie(hash, hmac) = hashAndHmacData(file, "", ht);
        }
        else
        {
            tie(hash, hmac) = hashAndHmacFile(file, "", ht);
        }

        Integer H = stringToCryptoInt(hash);
        Integer w = s.InverseMod(pohlig);   
        Integer u1 = (H*w) % pohlig;
        Integer u2 = (r*w) % pohlig;

        Integer g_u1 = a_exp_b_mod_c(g, u1, _contact.dh.mod());
        Integer g_u2 = a_exp_b_mod_c(pub2, u2, _contact.dh.mod());
        Integer v = ((g_u1 * g_u2) % _contact.dh.mod()) % pohlig;

        return v == r;
    }
    return 0;
}

std::tuple<std::string, std::string> AsymmetricAuthenticationExtension::hashAndHmacData(const std::string& data, const std::string& pass, HashType ht)
{
    using namespace std;
    unsigned char *hash, *hash2;
    Hash_Base *hc, *mac;
    getHash(ht, hc);
    getHmac(ht, mac, pass);
    
    hash = new unsigned char[getHashOutputSize(ht) / 8](), hash2 = new unsigned char[getHashOutputSize(ht) / 8]();
    

    mac->absorb((unsigned char*)&data[0], data.length());
    hc->absorb((unsigned char*)&data[0], data.length());

    mac->digest(hash, getHashOutputSize(ht) / 8);
    hc->digest(hash2, getHashOutputSize(ht) / 8);


    string res(""), res2("");
    res.append((char*)hash, getHashOutputSize(ht) / 8);
    res2.append((char*)hash2, getHashOutputSize(ht) / 8);
    
    delete[] hash;
    delete[] hash2;
    delete mac; 
    delete hc; 
    return make_tuple(res2, res);
}

std::tuple<std::string, std::string> AsymmetricAuthenticationExtension::hashAndHmacFile(const std::string& file, const std::string& pass, HashType ht)
{
    using namespace std;
    unsigned char *hash, *hash2;
    Hash_Base *mac, *hc;
    getHmac(ht, mac, pass);
    getHash(ht, hc);

    ifstream fi(file, ios::binary);
    hash = new unsigned char[getHashOutputSize(ht) / 8](), hash2 = new unsigned char[getHashOutputSize(ht) / 8]();
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
            hc->absorb((unsigned char*)block, x);
    
            fsize -= x;
        }
        if(fsize)
        {
            fi.read(block, fsize);
    
            mac->absorb((unsigned char*)block, fsize);
            hc->absorb((unsigned char*)block, fsize);
        }
        mac->digest(hash, getHashOutputSize(ht) / 8);
        hc->digest(hash2, getHashOutputSize(ht) / 8);
    }
    string res(""), res2("");
    res.append((char*)hash, getHashOutputSize(ht) / 8);
    res2.append((char*)hash2, getHashOutputSize(ht) / 8);
    fi.close();

    delete[] block;
    delete[] hash;
    delete[] hash2;
    delete mac; 
    delete hc; 
    return make_tuple(res2, res);
}

#define append_int(x) \
    con = cryptoIntToString(x); \
    len = con.length(); \
    res.append((char*)&len, sizeof(int16_t)); \
    res.append(con);

DataExtension AsymmetricAuthenticationExtension::outData() const
{
    using namespace std;
    DataExtension d;
    d.et = ExtensionType::ASYMMETRIC;
    d.data = out();
    return d;
}

std::string AsymmetricAuthenticationExtension::out() const
{
    using namespace std;
    std::string res;
   
    string con = _contact.out();
    int16_t len = con.length();

    res.append((char*)&len, sizeof(int16_t));
    res.append(con);

    append_int(r)
    append_int(s)

    return res;
}

Contact AsymmetricAuthenticationExtension::contact() const
{
    return _contact;
}

#define read_next(x) \
    len = *(int16_t*)&data[offset]; \
    offset += sizeof(int16_t);\
    con = data.substr(offset, len);\
    offset += len;

void AsymmetricAuthenticationExtension::parse(const std::string& data, int offset)
{
    using namespace std;
    
    string con;
    int16_t len;
    
    read_next()
    _contact.parse(con);

    read_next()
    r = stringToCryptoInt(con);

    read_next()
    s = stringToCryptoInt(con);
}
    

void AsymmetricAuthenticationExtension::parse(const DataExtension& d)
{
    parse(d.data);
}

#undef read_next
#undef append_int

AsymmetricAuthenticationSignature::AsymmetricAuthenticationSignature() : aae(), ht(HashType::SHA256)
{
}

AsymmetricAuthenticationSignature::AsymmetricAuthenticationSignature(const Contact& c, const std::string& file, const std::string& password, HashType ht, bool data) : aae(c, file, password, ht, data), ht(ht)
{

}

HashType AsymmetricAuthenticationSignature::hashType() const
{
    return ht;
}

Contact AsymmetricAuthenticationSignature::contact() const
{
    return aae.contact();
}
    
bool AsymmetricAuthenticationSignature::verify(std::string file, bool data)
{
    return aae.verify(file, ht, data);
}

std::string AsymmetricAuthenticationSignature::out() const
{
    std::string res;
    res.append((char*)&ht, sizeof(HashType));
    res.append(aae.out());
    return res;
}

void AsymmetricAuthenticationSignature::parse(const std::string& data, int offset)
{
    ht = *(HashType*)&data[offset];
    offset += sizeof(HashType);
    aae.parse(data, offset);
}