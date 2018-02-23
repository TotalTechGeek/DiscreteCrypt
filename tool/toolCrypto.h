#pragma once

#include "Parameters.h"
#include "../cryptopp/osrng.h"
#include "../cppcrypto/cppcrypto/cppcrypto.h"
#include <string>
#include <fstream>

// This is done for convenience.
#define aes256 rijndael128_256
#define aes192 rijndael128_192
#define aes128 rijndael128_128

static const char PWD[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$^&%*()-_[]{};:\\/<>,.?'~=+";

std::string getScrypt(const std::string& password, const std::string& salt, int N = 1 << 14, int p = 16, int r = 8, int len = 32)
{
    using namespace cppcrypto;

    std::string result;
    char* arr = new char[len]();

    hmac hc(sha256(), (const unsigned char*)password.c_str(), password.length());
    scrypt(hc, (const unsigned char*)salt.c_str(), salt.length(), N, r, p, (unsigned char*)arr, len);
     
    result.append(arr, len);
    delete[] arr;

    return result;
}


#if defined(_WIN32) || defined(_WIN64)

#include <conio.h>

// Works on Windows with Mingw32_64
std::string getPassword()
{
    std::string result;
    char c; 

    while((c=_getch()) != 13)
    {

        if(c == 8)
        {
            if(result.length()) 
            {
                result.pop_back();
                _putch('\b');
                _putch(' ');
                _putch('\b');
            }
        }
        else if(c == 3)
        {
            exit(0);
        }
        else
        {
            result += c;
            _putch('*');
        }        
         
    }

    _putch('\n');

    return result;
}
#else
std::string getPassword()
{
    std::string result; 
    getline(std::cin, result);
    return result;
}
#endif

std::string intToScrypt(const Integer& i, const ScryptParameters& sp, int keyLen)
{
    static std::string salt = "salt";
    unsigned char* dub1Out = new unsigned char[i.ByteCount()];
    i.Encode(dub1Out, i.ByteCount());
    return getScrypt((char*)dub1Out, salt, sp.N, sp.P, sp.R, keyLen);
}

Integer createContact(Contact& con, const DHParameters& dh, const ScryptParameters& sp)
{
    using namespace std;
    std::string identity, password;

    cout << "Identity: ";
    getline(cin, identity);

    if(identity == "") identity = "Anonymous";

    cout << "Password: ";
    password = getPassword();

    const int SALT_SIZE = 32;
    char* saltC = new char[SALT_SIZE];

    if(password == "")
    {
        OS_GenerateRandomBlock(true, (unsigned char*)saltC, SALT_SIZE);
        for(int i = 0; i < SALT_SIZE; i++)
        {
            password += PWD[saltC[i] % (sizeof(PWD)-1)];
        }
        cout << "Using Password: " << password << endl;
    }

    OS_GenerateRandomBlock(true, (unsigned char*)saltC, SALT_SIZE);
    
    std::string salt;
    salt.append(saltC);
    delete[] saltC;

    CryptoPP::Integer priv;
    priv.Decode((unsigned char*)getScrypt(password, salt, sp.N, sp.P, sp.R, sp.len).c_str(), sp.len);
    CryptoPP::Integer pub = a_exp_b_mod_c(dh.gen(), priv, dh.mod());

    PersonParameters p(identity, salt, pub);
    
    con.person = p;
    con.sp = sp;
    con.dh = dh;

    return priv; 
}

// This code will probably be replaced.
std::string getCipherName(const CryptoParams& cp)
{
    switch(cp.cipherType)
    {
        CIPHER_ENUM(MAKE_STRING) 
        default: return "";
    }
}

// This is somewhat of a factory design pattern.
void getCipher(const CryptoParams& cp, cppcrypto::block_cipher*& bc)
{
    using namespace cppcrypto;
    switch(cp.cipherType)
    {
        CIPHER_ENUM(MAKE_CONS)
        default:
        bc = new aes256;
        break;
    }

}

int getCipherKeySize(const CryptoParams& cp)
{
    int res;
    using namespace cppcrypto;
    block_cipher* bc;
    getCipher(cp, bc);
    res = bc->keysize();
    delete bc;
    return res;
}

int getCipherBlockSize(const CryptoParams& cp)
{
    int res;
    using namespace cppcrypto;
    block_cipher* bc;
    getCipher(cp, bc);
    res = bc->blocksize();
    delete bc;
    return res;
}

template <class T>
void encodeFile(T& c, const std::string& fileName)
{
    using namespace std;
    string o;
    ofstream f(fileName, ios::binary);

    if(f.good())
    {
        o = c.out();
        f.write(&o[0], o.length());
    }

    f.close();
}


template <class T>
void decodeFile(T& c, const std::string& fileName)
{
    using namespace std;
    string in;
    ifstream fi(fileName, ios::binary);

    if(fi.good())
    {
        while(!fi.eof()) in += fi.get();
        c.parse(in);
    }

    fi.close();
}

void decodeExchange(Exchange& ex, const std::string& fileName)
{
    using namespace std;
    ifstream fi(fileName, ios::binary);
    
    char* in = new char[sizeof(int16_t)];
    if(fi.good())
    {
        fi.read(in, sizeof(int16_t));
        
        int16_t len = *(int16_t*)in;

        delete[] in;

        in = new char[len];

        fi.read(in, len);
        
        string s;
        s.append(in, len);
        
        ex.parse(s);
    }

    delete[] in;
    fi.close();
}

void encryptFile(const std::string& fileName, const std::string& outputFile, const Exchange& ex, const unsigned char* key)
{
    using namespace std;
    using namespace cppcrypto;
    ifstream fi(fileName, ios::binary);
    ofstream fo(outputFile, ios::binary);

    string output(ex.out());
    int16_t len = (int16_t)output.length();

    // Write the header
    fo.write((char*)&len, sizeof(int16_t));
    fo.write(&output[0], len);

    // Gets the file size (hopefully)
    int fsize = 0;
    fi.seekg(0, ios::end);
    fsize = (int)fi.tellg() - fsize;
    fi.seekg(0, ios::beg);

    block_cipher *bc;
    getCipher(ex.cp, bc);

    int blocksize = (int)bc->blocksize() / 8;
    int keysize = (int)bc->keysize() / 8;

    unsigned char* iv = new unsigned char[blocksize];
    OS_GenerateRandomBlock(true, iv, blocksize);

    // write the iv
    fo.write((char*)iv, blocksize);

    
    char* inBuf = new char[blocksize];
    char* outBuf = new char[blocksize];

    ctr c(*bc);
    c.init(key, keysize, iv, blocksize);

    cout << fsize << endl;

    if(fi.good() && !fi.bad())
    {
        while(fsize > blocksize)
        {
            fi.read(inBuf, blocksize);
            c.encrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            fo.write(outBuf, blocksize);
            fsize -= blocksize;
        }

        if(fsize)
        {
            fi.read(inBuf, fsize);
            c.encrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            fo.write(outBuf, fsize);
        }
    }

    delete bc;
    delete[] iv;
    delete[] inBuf;
    delete[] outBuf;
    fi.close();
    fo.close();
}


void decryptFile(const std::string& fileName, const std::string& outputFile, const Exchange& ex, const unsigned char* key)
{
    using namespace std;
    using namespace cppcrypto;
    ifstream fi(fileName, ios::binary);
    ofstream fo(outputFile, ios::binary);
    
    // Gets the file size (hopefully)
    int fsize = 0;
    fi.seekg(0, ios::end);
    fsize = (int)fi.tellg() - fsize;
    fi.seekg(0, ios::beg);

    char* lenRead = new char[sizeof(int16_t)];
    fi.read(lenRead, sizeof(int16_t));
    int16_t len = *(int16_t*)lenRead;
    delete[] lenRead;

    //skip the header
    fi.ignore(len);

    fsize -= len;
    fsize -= sizeof(int16_t);

    block_cipher *bc;
    getCipher(ex.cp, bc);

    int blocksize = (int)bc->blocksize() / 8;
    int keysize = (int)bc->keysize() / 8;

    unsigned char* iv = new unsigned char[blocksize];
    
    // read the iv
    fi.read((char*)iv, blocksize);
    fsize -= blocksize;

    char* inBuf = new char[blocksize];
    char* outBuf = new char[blocksize];

    ctr c(*bc);
    c.init(key, keysize, iv, blocksize);

    cout << fsize << endl; 

    if(fi.good() && !fi.bad())
    {
        while(fsize > blocksize)
        {
            fi.read(inBuf, blocksize);
            c.decrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            fo.write(outBuf, blocksize);
            fsize -= blocksize;
        }

        if(fsize)
        {
            fi.read(inBuf, fsize);
            c.decrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            fo.write(outBuf, fsize);
        }
    }

    delete bc;
    delete[] iv;
    delete[] inBuf;
    delete[] outBuf;
    fi.close();
    fo.close();
}