#pragma once

#include "Parameters.h"
#include "../cryptopp/osrng.h"
#include "../cppcrypto/cppcrypto/cppcrypto.h"
#include <string>
#include <iostream>
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
#include <termios.h>
#include <unistd.h>
int getch() 
{
    int ch;
    struct termios t_old, t_new;

    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);
    return ch;
}


std::string getPassword()
{
    using namespace std;
    const char BACKSPACE = 127;
    const char RETURN = 10;

    string password;
    unsigned char ch = 0;


    while((ch=getch())!=RETURN)
    {
        if (ch==BACKSPACE)
        {
            if(password.length() != 0)
            {
                cout << "\b \b";
                password.resize(password.length()-1);
            }
        }
        else
        {
            password += ch;
            cout << '*';
        }
    }

    cout << endl;
    return password;
}
#endif

std::string intToScrypt(const CryptoPP::Integer& i, const ScryptParameters& sp, int keyLen, const FileProperties& fp)
{
    unsigned char* dub1Out = new unsigned char[i.ByteCount()];
    i.Encode(dub1Out, i.ByteCount());
    return getScrypt((char*)dub1Out, fp.hash, sp.N, sp.P, sp.R, keyLen);
}

CryptoPP::Integer createContact(Contact& con, const DHParameters& dh, const ScryptParameters& sp)
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
        CryptoPP::OS_GenerateRandomBlock(true, (unsigned char*)saltC, SALT_SIZE);
        for(int i = 0; i < SALT_SIZE; i++)
        {
            password += PWD[saltC[i] % (sizeof(PWD)-1)];
        }
        cout << "Using Password: " << password << endl;
    }

    CryptoPP::OS_GenerateRandomBlock(true, (unsigned char*)saltC, SALT_SIZE);
    
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
std::string getCipherName(CipherType p)
{
    switch(p)
    {
        CIPHER_ENUM(MAKE_STRING) 
        default: return "";
    }
}

// This is somewhat of a factory design pattern.
void getCipher(CipherType p, cppcrypto::block_cipher*& bc)
{
    using namespace cppcrypto;
    switch(p)
    {
        CIPHER_ENUM(MAKE_CONS)
        default:
        bc = new aes256;
        break;
    }
}

void getHash(HashType h, cppcrypto::crypto_hash*& bc)
{
    using namespace cppcrypto;
    switch(h)
    {
        HASH_ENUM(MAKE_CONS)
        default:
        bc = new sha256;
        break;
    }
}


std::string getHashName(HashType h)
{
    switch(h)
    {
        HASH_ENUM(MAKE_STRING)
        default:
        return "";
    }
}

int getHashOutputSize(HashType h)
{
    int res;
    using namespace cppcrypto;
    crypto_hash* bc;
    getHash(h, bc);
    res = bc->hashsize();
    delete bc;
    return res;
}

int getCipherKeySize(CipherType p)
{
    int res;
    using namespace cppcrypto;
    block_cipher* bc;
    getCipher(p, bc);
    res = bc->keysize();
    delete bc;
    return res;
}

int getCipherBlockSize(CipherType p)
{
    int res;
    using namespace cppcrypto;
    block_cipher* bc;
    getCipher(p, bc);
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

void decodeEncrypted(Exchange& ex, FileProperties& fp, const std::string& fileName)
{
    using namespace std;
    ifstream fi(fileName, ios::binary);
    
    if(fi.good())
    {
        char* in = new char[sizeof(int16_t)];

        // Get the size of the FP
        fi.read(in, sizeof(int16_t));
        int16_t len = *(int16_t*)in;

        // Read in the FP
        char* block = new char[len];
        fi.read(block, len);
        
        string s;
        s.append(block, len);

        fp.parse(s);
        delete[] block;

        // Get the size of the ex
        fi.read(in, sizeof(int16_t));
        len = *(int16_t*)in;

        // Read in the Exchange
        block = new char[len];
        fi.read(block, len);
        s = "";
        s.append(block, len);
        ex.parse(s);
        delete[] block;
        delete[] in;
        
    }

    fi.close();
}


std::string hashPad(std::string hash, int blockSize)
{
    if(hash.length() < blockSize)
    {
        unsigned char *c = new unsigned char[blockSize - hash.length()]();
        CryptoPP::OS_GenerateRandomBlock(true, c, blockSize - hash.length());
        hash.append((char*)c, blockSize - hash.length());
        delete[] c;
    }

    return hash;
}

void hmacFile(const std::string& filename, FileProperties& fp)
{
    using namespace cppcrypto;
    using namespace std;

    // Establish a key.
    int keySize = getCipherKeySize(fp.cp.cipherType) / 8;
    int blockSize = getCipherBlockSize(fp.cp.cipherType) / 8;
    unsigned char *key = new unsigned char[keySize];
    CryptoPP::OS_GenerateRandomBlock(true, key, keySize);
    fp.key = "";
    fp.key.append((char*)key, keySize);

    unsigned char* hash;
    crypto_hash* bc;
    
    getHash(fp.ht, bc);

    hmac mac(*bc, key, keySize);
    mac.init();

    ifstream fi(filename, ios::binary);
    
    hash = new unsigned char[bc->hashsize() / 8]();
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
            fsize -= x;
        }

        if(fsize)
        {
            fi.read(block, fsize);
            mac.update((unsigned char*)block, fsize);
        }

        mac.final(hash);
    }
    
    fp.hash = "";
    fp.hash.append((char*)hash, bc->hashsize() / 8);

    fp.hash = hashPad(fp.hash, blockSize);

    fi.close();
    delete[] key;
    delete[] block;
    delete[] hash;
    delete bc;
}


void encryptFile(const std::string& fileName, const std::string& outputFile, const Exchange& ex, const FileProperties& fp, const unsigned char* key)
{
    using namespace std;
    using namespace cppcrypto;
    ifstream fi(fileName, ios::binary);
    ofstream fo(outputFile, ios::binary);

    block_cipher *bc;
    getCipher(fp.cp.cipherType, bc);

    int blocksize = (int)bc->blocksize() / 8;
    int keysize = (int)bc->keysize() / 8;

    string output = fp.out();
    int16_t len = (int16_t)output.length();


    // Write the header (FP)
    fo.write((char*)&len, sizeof(int16_t));
    fo.write(&output[0], len);

    output = ex.out();
    len = (int16_t)output.length();


    // Write the exchange (EX)
    fo.write((char*)&len, sizeof(int16_t));
    fo.write(&output[0], len);


    
    // Using the file's hash at the moment.
    std::string h = fp.hash;
    while(h.length() > blocksize) h.pop_back();
    unsigned char* iv = (unsigned char*)&h[0];


    ctr c(*bc);
    c.init(key, keysize, iv, blocksize);
    
    
    int k = keysize + (blocksize - keysize % blocksize);
    
    unsigned char* ikey = (unsigned char*)&fp.key[0], *okey = new unsigned char[k];
    // fi.read((char*)ikey, keysize);

    for(int i = 0; i < keysize; i += blocksize)
    {
        c.encrypt(ikey + i, blocksize, okey + i);
    }

    fo.write((char*)okey, keysize);


    delete bc;

    // Use the Key.
    getCipher(fp.cp.cipherType, bc);
    ctr c2(*bc);
    c2.init(ikey, keysize, iv, blocksize);
    

    // Gets the file size (hopefully)
    int fsize = 0;
    fi.seekg(0, ios::end);
    fsize = (int)fi.tellg() - fsize;
    fi.seekg(0, ios::beg);


    char* inBuf = new char[blocksize];
    char* outBuf = new char[blocksize];


    if(fi.good() && !fi.bad())
    {
        while(fsize > blocksize)
        {
            fi.read(inBuf, blocksize);
            c2.encrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            fo.write(outBuf, blocksize);
            fsize -= blocksize;
        }

        if(fsize)
        {
            fi.read(inBuf, fsize);
            c2.encrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            fo.write(outBuf, fsize);
        }
    }

    delete bc;
    delete[] okey;
    delete[] inBuf;
    delete[] outBuf;
    fi.close();
    fo.close();
}


char decryptFile(const std::string& fileName, const std::string& outputFile, const Exchange& ex, const FileProperties& fp, const unsigned char* key)
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

    //skip the header
    fi.read(lenRead, sizeof(int16_t));
    int16_t len = *(int16_t*)lenRead;
    fi.ignore(len);

    fsize -= len;
    fsize -= sizeof(int16_t);
    
    // Skip the exchange
    fi.read(lenRead, sizeof(int16_t));
    len = *(int16_t*)lenRead;
    fi.ignore(len);

    fsize -= len;
    fsize -= sizeof(int16_t);
    delete[] lenRead;

    block_cipher *bc;
    crypto_hash *hc; 
    getHash(fp.ht, hc);
    getCipher(fp.cp.cipherType, bc);


    unsigned char* hash = new unsigned char[hc->hashsize() / 8];
    
    int blocksize = (int)bc->blocksize() / 8;
    int keysize = (int)bc->keysize() / 8;

    // Using the file's hash at the moment.
    std::string h = fp.hash;
    while(h.length() > blocksize) h.pop_back();
    unsigned char* iv = (unsigned char*)&h[0];

    char* inBuf = new char[blocksize];
    char* outBuf = new char[blocksize];

    ctr c(*bc);
    c.init(key, keysize, iv, blocksize);

    int k = keysize + (blocksize - keysize % blocksize);
    
    unsigned char* ikey = new unsigned char[k], *okey = new unsigned char[k];
    fi.read((char*)ikey, keysize);
    fsize -= keysize;

    for(int i = 0; i < keysize; i += blocksize)
    {
        c.decrypt(ikey + i, blocksize, okey + i);
    }

    delete bc;

    hmac mac(*hc, okey, keysize);
    mac.init();

    // Use the Key.
    getCipher(fp.cp.cipherType, bc);
    ctr c2(*bc);
    c2.init(okey, keysize, iv, blocksize);

    if(fi.good() && !fi.bad())
    {
        while(fsize > blocksize)
        {
            fi.read(inBuf, blocksize);
            c2.decrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            mac.update((unsigned char*)outBuf, blocksize);
            fo.write(outBuf, blocksize);
            fsize -= blocksize;
        }

        if(fsize)
        {
            fi.read(inBuf, fsize);
            c2.decrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            mac.update((unsigned char*)outBuf, fsize);
            fo.write(outBuf, fsize);
        }
    }

    mac.final(hash);
    char valid = 1;

    for(int i = 0; i < hc->hashsize() / 8; i++)
    {
        valid = valid && hash[i] == (unsigned char)fp.hash[i];
    }

    delete hc;
    delete bc;
    delete[] ikey;
    delete[] okey;
    delete[] hash;
    delete[] inBuf;
    delete[] outBuf;
    fi.close();
    fo.close();

    return valid;
}