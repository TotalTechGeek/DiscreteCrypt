#include "Parameters.h"
#include "toolCrypto.h"

// Eventually we'll break this into separate files. 
DHParameters::DHParameters() : modulus("0"), generator("0")
{}

DHParameters::DHParameters(const DHParameters& d) : modulus(d.modulus), generator(d.generator)
{}

DHParameters::DHParameters(const std::string& in, int offset) : modulus("0"), generator("0")
{
    parse(in, offset);
}

DHParameters::DHParameters(const char* gen, const char* mod) : modulus(mod), generator(gen)
{}

 DHParameters::DHParameters(const std::string& gen, const std::string& mod) : modulus(mod.c_str()), generator(gen.c_str())
{}

void DHParameters::parse(const std::string& in, int offset)
{
    int16_t len1, len2;
    len1 = *(int16_t*)&in[offset];
    len2 = *(int16_t*)&in[offset + sizeof(int16_t)];
    
    modulus.Decode((unsigned char*)&in[offset + 2 * sizeof(int16_t)], len1);
    generator.Decode((unsigned char*)&in[offset + 2 * sizeof(int16_t) + len1], len2);
}

int DHParameters::len() const
{
    return modulus.ByteCount() + generator.ByteCount() + sizeof(int16_t) * 2;
}


std::tuple<CryptoPP::Integer, CryptoPP::Integer> DHParameters::pohlig() const
{
    using CryptoPP::Integer;
    Integer x = mod() - 1;
    Integer y = 1;
    for(int i = 2; i < 65536; i++)
    {
        while(!(x % i))
        {
            x /= i;
            y *= i;
        }
    }

    return std::make_tuple(x, y);
}


CryptoPP::Integer DHParameters::mod() const
{
    return modulus;
}

void DHParameters::mod(CryptoPP::Integer x)
{
    modulus = x;
}

CryptoPP::Integer DHParameters::gen() const
{
    return generator;
}

void DHParameters::gen(CryptoPP::Integer x)
{
    generator = x;
}
// Currently a very dumb hack.
std::string DHParameters::out() const
{
    unsigned char* out1 = new unsigned char[modulus.ByteCount()];
    unsigned char* out2 = new unsigned char[generator.ByteCount()];
    std::string result;
    
    //append the lengths
    int16_t len1 = (int16_t)modulus.ByteCount(), len2 = (int16_t)generator.ByteCount();
    result.append((char*)(&len1), sizeof(int16_t));
    result.append((char*)(&len2), sizeof(int16_t));
    modulus.Encode(out1, modulus.ByteCount());
    result.append((char*)out1, modulus.ByteCount());
    
    generator.Encode(out2, generator.ByteCount());
    result.append((char*)out2, generator.ByteCount());
    
    delete[] out1;
    delete[] out2;
    return result;
}

CipherParams::CipherParams() : cipherType(AES256), mode()
{
}

CipherParams::CipherParams(const CipherParams& c) : cipherType(c.cipherType), mode(c.mode)
{
}

ScryptParameters::ScryptParameters() : N(DISCRETECRYPT_DEFAULT_N), P(DISCRETECRYPT_DEFAULT_P), R(DISCRETECRYPT_DEFAULT_R), len(DISCRETECRYPT_DEFAULT_LEN)
{
}

ScryptParameters::ScryptParameters(const ScryptParameters& s) : N(s.N), P(s.P), R(s.R), len(s.len)
{
}

ScryptParameters::ScryptParameters(int32_t N, int32_t P, int32_t R, int32_t len) : N(N), P(P), R(R), len(len)
{
}

PersonParameters::PersonParameters()
{
}

PersonParameters::PersonParameters(const PersonParameters& p) : identity(p.identity), salt(p.salt), publicKey(p.publicKey)
{
}

PersonParameters::PersonParameters(const std::string& identity, const std::string& salt, char* publicKey) : identity(identity), salt(salt), publicKey(publicKey)
{
}

PersonParameters::PersonParameters(const std::string& identity, const std::string& salt, CryptoPP::Integer publicKey) : identity(identity), salt(salt), publicKey(publicKey)
{
}

PersonParameters::PersonParameters(const std::string& in, int offset) : publicKey("0")
{
    parse(in, offset);
}

void PersonParameters::parse(const std::string& in, int offset)
{
    int16_t len1, len2, len3;
    len1 = *(int16_t*)&in[offset + 0*sizeof(int16_t)];
    len2 = *(int16_t*)&in[offset + 1*sizeof(int16_t)];
    len3 = *(int16_t*)&in[offset + 2*sizeof(int16_t)];
    identity = in.substr(offset + 3*sizeof(int16_t), len1);
    salt = in.substr(offset + 3*sizeof(int16_t) + len1, len2);
    publicKey.Decode((unsigned char*)&in[offset + 3*sizeof(int16_t) + len1 + len2], len3);
}

int PersonParameters::len() const
{
    return salt.length() + identity.length() + publicKey.ByteCount() + sizeof(int16_t) * 3;
}

std::string PersonParameters::saltHex() const
{
    return to_hex(salt);
}

std::string PersonParameters::out() const
{
    std::string result;
    int16_t len = identity.length();
    result.append((char*)&len, sizeof(int16_t));
    len = salt.length();
    result.append((char*)&len, sizeof(int16_t));
            
    len = (int16_t)publicKey.ByteCount();
    result.append((char*)&len, sizeof(int16_t));
    
    unsigned char* out1 = new unsigned char[len];
    publicKey.Encode(out1, len);
    
    result.append(identity);
    result.append(salt);
    result.append((char*)out1, len);
    delete[] out1;
    return result;
}


Contact::Contact()
{
}

Contact::Contact(const Contact& c) : person(c.person), sp(c.sp), dh(c.dh)
{
}

Contact::Contact(const PersonParameters& p, const ScryptParameters& sp, const DHParameters& dh) : dh(dh), sp(sp), person(p)
{
}

Contact::Contact(const std::string& in, int offset) 
{
    parse(in, offset);
}

void Contact::parse(const std::string& in, int offset)
{
    person.parse(in, offset);
    sp = *(ScryptParameters*)&in[offset + person.len()];
    dh.parse(in, sizeof(ScryptParameters) + offset + person.len());
}

std::string Contact::out() const
{
    std::string result;
    result.append(person.out());
    result.append((char*)&sp, sizeof(sp));
    result.append(dh.out());
    return result;
}

std::string Contact::uid(HashType ht) const
{
    std::string result;

    Contact con(*this);

    // Don't use the identity, this could be modified.
    con.person.identity = "";
    Hash_Base *hc;

    getHash(ht, hc);
    unsigned char* hashOut = new unsigned char[getHashOutputSize(ht) / 8]();

    std::string str = con.out();
    hc->absorb((unsigned char*)&str.c_str()[0], str.length());
    hc->digest(hashOut, getHashOutputSize(ht) / 8);
    result.append((char*)hashOut, getHashOutputSize(ht) / 8);
    delete[] hashOut;
    delete hc;
    return result;
}

std::string Contact::uidHex(HashType ht) const
{
    return to_hex(uid(ht));
}


bool Contact::verify(std::string pass) const
{
    using CryptoPP::Integer;
    // Compute the private and public values.
    Integer priv;
    priv.Decode((unsigned char*)getScrypt(pass, person.salt, sp.N, sp.P, sp.R, sp.len).c_str(), sp.len);
    Integer pub = a_exp_b_mod_c(dh.gen(), priv, dh.mod());
    return pub == person.publicKey;
}


FileProperties::FileProperties(CipherParams cp, HashType ht) : ht(ht), cp(cp)
{
    
}

// simple parsing.
void FileProperties::parse(const std::string& in, int offset)
{
    version = in[offset];
    offset += sizeof(char);

    recipients = *(int16_t*)&in[offset];
    offset += sizeof(int16_t);
    
    extensions = *(int16_t*)&in[offset];
    offset += sizeof(int16_t);

    cp = *(CipherParams*)&in[offset];
    offset += sizeof(CipherParams);
    
    ht = *(HashType*)&in[offset];
    offset += sizeof(HashType);
    
    int16_t len = *(int16_t*)&in[offset];
    offset += sizeof(int16_t);
    
    hash = in.substr(offset, len);
}
    
std::string FileProperties::out() const
{
    std::string res; 
    int16_t len;
    len = (int16_t)(hash.length());
    
    res.append((char*)&version, sizeof(char));
    res.append((char*)&recipients, sizeof(int16_t));
    res.append((char*)&extensions, sizeof(int16_t));
    res.append((char*)&cp, sizeof(CipherParams));
    res.append((char*)&ht, sizeof(HashType));
    res.append((char*)&len, sizeof(int16_t));
    res.append(hash);
    return res;
}


Exchange::Exchange()
{}

Exchange::Exchange(const Exchange& ex) : alice(ex.alice), bob(ex.bob), sp(ex.sp), dh(ex.dh), computed(ex.computed)
{}

Exchange::Exchange(const PersonParameters& a, const PersonParameters& b, const ScryptParameters& s, const CipherParams& cp, const DHParameters& dh) : alice(a), bob(b), sp(s), dh(dh)
{
}

// Such a hack, let us hope it works. :D
Exchange::Exchange(const std::string& in, int offset) 
{
    parse(in, offset);
}

void Exchange::parse(const std::string& in, int offset)
{
    alice.parse(in, offset);
    bob.parse(in, alice.len() + offset);
    sp = *(ScryptParameters*)&in[offset + alice.len() + bob.len()];
    dh.parse(in, sizeof(ScryptParameters) + offset + alice.len() + bob.len());
}
    
std::string Exchange::out() const
{
    std::string result;
    result.append(alice.out());
    result.append(bob.out());
    result.append((char*)&sp, sizeof(ScryptParameters));
    result.append(dh.out());
    return result;
}

Contact Exchange::aliceContact() const
{
    Contact con;
    con.sp = sp;
    con.dh = dh;
    con.person = alice;
    return con;
}

Contact Exchange::bobContact() const
{
    Contact con;
    con.sp = sp;
    con.dh = dh;
    con.person = bob;
    return con;
}

std::string DataExtension::out() const
{
    std::string result;

    int16_t len = data.size();
    result.append((char*)&et, sizeof(ExtensionType));
    
    result.append((char*)&len, sizeof(int16_t));
    result.append(data);
    
    return result;
}

 void DataExtension::parse(const std::string& in, int offset)
 {
    et = *(ExtensionType*)&in[offset];
    offset += sizeof(ExtensionType);

    int16_t len;
    len = *(int16_t*)&in[offset];
    offset += sizeof(int16_t);

    data = in.substr(offset, len);
 }
