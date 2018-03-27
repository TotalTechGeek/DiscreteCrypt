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

AsymmetricAuthenticationExtension::AsymmetricAuthenticationExtension(const Contact& c, const std::string& file, const std::string& password, HashType ht) : r("0"), s("0"), _contact(c)
{
    using namespace std;
    if(c.verify(password))
    {
        Integer pohlig, factors;
        tie(pohlig, factors) = _contact.dh.pohlig();    
        
        // This converts the public key to its proper DSA public key.
        Integer g = a_exp_b_mod_c(_contact.dh.gen(), factors, _contact.dh.mod());
        
        string hash, hmac;
        tie(hash, hmac) = hashAndHmacFile(file, password, ht);

        Integer x = passwordToPrivate(password, _contact.person.salt, _contact.sp);

        Integer k = stringToCryptoInt(hmac), H = stringToCryptoInt(hash);
        
        r = a_exp_b_mod_c(g, k, _contact.dh.mod()) % pohlig;
        s = (k.InverseMod(pohlig) * (H + x*r)) % pohlig;
    }

}

bool AsymmetricAuthenticationExtension::verify(std::string file, HashType ht)
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
        tie(hash, hmac) = hashAndHmacFile(file, "", ht);

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

std::tuple<std::string, std::string> AsymmetricAuthenticationExtension::hashAndHmacFile(const std::string& file, const std::string& pass, HashType ht)
{
    using namespace cppcrypto;
    using namespace std;
    unsigned char *hash, *hash2;
    crypto_hash *bc, *hc;
    getHash(ht, bc);
    getHash(ht, hc);

    hmac mac(*bc, pass);
    
    mac.init();
    hc->init(); 

    ifstream fi(file, ios::binary);
    hash = new unsigned char[bc->hashsize() / 8](), hash2 = new unsigned char[hc->hashsize() / 8]();
    int x = bc->blocksize() / 8;
    if(x == 0) x = bc->hashsize() / 8;
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
    
            mac.update((unsigned char*)block, x);
            hc->update((unsigned char*)block, x);
    
            fsize -= x;
        }
        if(fsize)
        {
            fi.read(block, fsize);
    
            mac.update((unsigned char*)block, fsize);
            hc->update((unsigned char*)block, fsize);
        }
        mac.final(hash);
        hc->final(hash2);
    }
    string res(""), res2("");
    res.append((char*)hash, bc->hashsize() / 8);
    res2.append((char*)hash2, hc->hashsize() / 8);
    fi.close();

    delete[] block;
    delete[] hash;
    delete[] hash2;
    delete bc; 
    delete hc; 
    return std::make_tuple(res2, res);
}

#define append_int(x) \
    con = cryptoIntToString(x); \
    len = con.length(); \
    d.data.append((char*)&len, sizeof(int16_t)); \
    d.data.append(con);

DataExtension AsymmetricAuthenticationExtension::out() const
{
    using namespace std;
    DataExtension d;

    d.et = ExtensionType::ASYMMETRIC;

    string con = _contact.out();
    int16_t len = con.length();

    
    d.data.append((char*)&len, sizeof(int16_t));
    d.data.append(con);

    append_int(r)
    append_int(s)

    return d;
}

Contact AsymmetricAuthenticationExtension::contact() const
{
    return _contact;
}

#define read_next(x) \
    len = *(int16_t*)&d.data[offset]; \
    offset += sizeof(int16_t);\
    con = d.data.substr(offset, len);\
    offset += len;

void AsymmetricAuthenticationExtension::parse(const DataExtension& d)
{
    using namespace std;
    
    int offset = 0;

    string con;
    int16_t len;
    
    read_next()
    _contact.parse(con);

    read_next()
    r = stringToCryptoInt(con);

    read_next()
    s = stringToCryptoInt(con);
}

#undef read_next
#undef append_int