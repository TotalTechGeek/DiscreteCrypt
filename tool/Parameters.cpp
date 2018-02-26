#include "Parameters.h"

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

ScryptParameters::ScryptParameters() : N(1 << 14), P(16), R(8), len(32)
{
}

ScryptParameters::ScryptParameters(const ScryptParameters& s) : N(s.N), P(s.P), R(s.R), len(s.len)
{
}

ScryptParameters::ScryptParameters(int32_t N, int32_t P, int32_t R, int32_t len) : N(N), P(P), R(R), len(len)
{
}


Contact::Contact()
{
}

Contact::Contact(const Contact& c) : person(c.person), sp(c.sp), dh(c.dh)
{
}

Contact::Contact(const PersonParameters& p, const ScryptParameters& sp, const DHParameters& dh) : dh(dh), sp(sp), person(person)
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
    res.append((char*)&cp, sizeof(CipherParams));
    res.append((char*)&ht, sizeof(HashType));
    res.append((char*)&len, sizeof(int16_t));
    res.append(hash);
    return res;
}


Exchange::Exchange()
{}

Exchange::Exchange(const Exchange& ex) : alice(ex.alice), bob(ex.bob), sp(ex.sp), dh(ex.dh)
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