#include "toolCrypto.h"
#include "Parameters.h"
#include "../cryptopp/osrng.h"
#include "AsymmetricAuthenticationExtension.h"
#include "../cppcrypto/cppcrypto/cppcrypto.h"
#include <string>
#include <iostream>
#include <fstream>

// This is done for convenience.
#define aes256 rijndael128_256
#define aes192 rijndael128_192
#define aes128 rijndael128_128

static const char PWD[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$^&%*()-_[]{};:\\/<>,.?'~=+";

std::string getScrypt(const std::string& password, const std::string& salt, int N, int p, int r, int len)
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
#include <stdio.h>
#include <io.h>

// Works on Windows with Mingw32_64
std::string getPassword()
{
    std::string result;

    // For Pipes
    if(!_isatty(_fileno(stdin)))
    {
        getline(std::cin, result);
        return result;
    }

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
    string password;
    
    // For Pipes
    if(!isatty(fileno(stdin)))
    {
        getline(cin, password);
        return password;
    }


    const char BACKSPACE = 127;
    const char RETURN = 10;

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
    unsigned char* dub1Out = new unsigned char[i.ByteCount()]();
    i.Encode(dub1Out, i.ByteCount());
    std::string pass("");
    pass.append((char*)dub1Out, i.ByteCount());
    delete[] dub1Out;
    return getScrypt(pass, fp.hash, sp.N, sp.P, sp.R, keyLen);
}

std::string cryptoIntToString(const CryptoPP::Integer& n)
{
    unsigned char* buf = new unsigned char[n.ByteCount()];
    n.Encode(buf, n.ByteCount());
    std::string res;
    res.append((char*)buf, n.ByteCount());
    delete[] buf;
    return res;
}


CryptoPP::Integer stringToCryptoInt(const std::string& s)
{
    CryptoPP::Integer res;
    res.Decode((unsigned char*)&s[0], s.length());
    return res;
}

CryptoPP::Integer passwordToPrivate(const std::string& pass, const std::string& salt, const ScryptParameters& sp)
{   
    std::string scr = getScrypt(pass, salt, sp.N, sp.P, sp.R, sp.len);
    CryptoPP::Integer priv;
    priv.Decode((unsigned char*)scr.c_str(), scr.length());
    return priv;
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
    char* saltC = new char[SALT_SIZE]();

    if(password == "")
    {
        CryptoPP::OS_GenerateRandomBlock(false, (unsigned char*)saltC, SALT_SIZE);
        for(int i = 0; i < SALT_SIZE; i++)
        {
            password += PWD[saltC[i] % (sizeof(PWD)-1)];
        }
        cout << "Using Password: " << password << endl;
    }

    CryptoPP::OS_GenerateRandomBlock(false, (unsigned char*)saltC, SALT_SIZE);
    
    std::string salt;
    salt.append(saltC, SALT_SIZE);
    delete[] saltC;

    CryptoPP::Integer priv;
    std::string scr = getScrypt(password, salt, sp.N, sp.P, sp.R, sp.len);
    priv.Decode((unsigned char*)scr.c_str(), scr.length());
    CryptoPP::Integer pub = a_exp_b_mod_c(dh.gen(), priv, dh.mod());

    PersonParameters p(identity, salt, pub);
    
    con.person = p;
    con.sp = sp;
    con.dh = dh;

    return priv; 
}

CryptoPP::Integer createContact(Contact& con, const DHParameters& dh, const ScryptParameters& sp, const std::string& identity, std::string& password)
{
    using namespace std;
  

    const int SALT_SIZE = 32;
    char* saltC = new char[SALT_SIZE]();

    if(password == "")
    {
        CryptoPP::OS_GenerateRandomBlock(false, (unsigned char*)saltC, SALT_SIZE);
        for(int i = 0; i < SALT_SIZE; i++)
        {
            password += PWD[saltC[i] % (sizeof(PWD)-1)];
        }
        cout << "Using Password: " << password << endl;
    }

    CryptoPP::OS_GenerateRandomBlock(false, (unsigned char*)saltC, SALT_SIZE);
    
    std::string salt;
    salt.append(saltC, SALT_SIZE);
    delete[] saltC;

    CryptoPP::Integer priv;
    std::string scrypt = getScrypt(password, salt, sp.N, sp.P, sp.R, sp.len);
    priv.Decode((unsigned char*)scrypt.c_str(), scrypt.length());
    CryptoPP::Integer pub = a_exp_b_mod_c(dh.gen(), priv, dh.mod());

    PersonParameters p(identity, salt, pub);
    con.person = p;
    con.sp = sp;
    con.dh = dh;

    return priv; 
}


CryptoPP::Integer createContact(Contact& con, const DHParameters& dh, const ScryptParameters& sp, Contact* contact, std::string& password)
{
    using namespace std;
  
    CryptoPP::Integer priv;
    std::string scrypt = getScrypt(password, contact->person.salt, sp.N, sp.P, sp.R, sp.len);
    priv.Decode((unsigned char*)scrypt.c_str(), scrypt.length());
    CryptoPP::Integer pub = a_exp_b_mod_c(dh.gen(), priv, dh.mod());

    PersonParameters p(contact->person.identity, contact->person.salt, pub);
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

void decodeEncrypted(std::vector<Exchange>& exchanges, FileProperties& fp, const std::string& fileName)
{
    using namespace std;
    ifstream fi(fileName, ios::binary);
    Exchange ex;
    
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

        // Reads in all the exchanges.
        for(int i = 0; i < fp.recipients; i++)
        {
            // Get the size of the ex
            fi.read(in, sizeof(int16_t));
            len = *(int16_t*)in;

            // Read in the Exchange
            block = new char[len];
            fi.read(block, len);
            s = "";
            s.append(block, len);
            ex.parse(s);
            exchanges.push_back(ex);
            delete[] block;
        }

        delete[] in;
        
    }

    fi.close();
}

std::string hashPad(std::string hash, int blockSize)
{
    if(hash.length() < blockSize)
    {
        unsigned char *c = new unsigned char[blockSize - hash.length()]();
        CryptoPP::OS_GenerateRandomBlock(false, c, blockSize - hash.length());
        hash.append((char*)c, blockSize - hash.length());
        delete[] c;
    }

    return hash;
}

// Creates a key for the file.
void createFileKey(FileProperties& fp)
{
    int keySize = getCipherKeySize(fp.cp.cipherType) / 8;
    int blockSize = getCipherBlockSize(fp.cp.cipherType) / 8;
    unsigned char *key = new unsigned char[keySize];
    CryptoPP::OS_GenerateRandomBlock(false, key, keySize);
    fp.key = "";
    fp.key.append((char*)key, keySize);
    delete[] key;
}

// Todo: Create a new method to compute a hash of the file for the extensions.
// Since extensions will be included in the encrypted payload, HMACs will not be necessary
// even if there were a way to extract a hash from a signature.

void hmacFile(const std::string& filename, const std::vector<DataExtension>& extensions, FileProperties& fp)
{
    using namespace cppcrypto;
    using namespace std;

    // Establish a key.
    int keySize = getCipherKeySize(fp.cp.cipherType) / 8;
    int blockSize = getCipherBlockSize(fp.cp.cipherType) / 8;
    createFileKey(fp);

    unsigned char* hash;
    crypto_hash* bc;
    
    getHash(fp.ht, bc);

    hmac mac(*bc, (unsigned char*)fp.key.c_str(), keySize);
    mac.init();

    // Hashes each of the extensions.
    for(int i = 0; i < extensions.size(); i++)
    {
        string output = extensions[i].out();
        int16_t len = (int16_t)output.length();

        // Write the extensions
        mac.update((unsigned char*)&len, sizeof(int16_t));
        mac.update((unsigned char*)&output[0], len);
    }

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
    delete[] block;
    delete[] hash;
    delete bc;
}


// The functionality is thought out, it's just not properly implemented.
// The good news is that this is supported now, which means that when the behavior is implemented, 
// older versions won't be negatively affected by its addition.
DataExtension symmetricSign(const FileProperties& fp, const std::string& password)
{
    using namespace cppcrypto;
    unsigned char* hash;
    crypto_hash* bc;
    
    getHash(fp.ht, bc);

    hash = new unsigned char[bc->hashsize() / 8]();

    hmac mac(*bc, password);
    mac.init();

    mac.update((unsigned char*)fp.hash.c_str(), fp.hash.length());
    mac.final(hash);

    DataExtension result;
    result.data.append((char*)hash, bc->hashsize() / 8);

    result.et = ExtensionType::SYMMETRIC;
    return result;
}


void encryptFile(const std::string& fileName, const std::string& outputFile, const std::vector<Contact>& recipients, const std::vector<DataExtension>& extensions, const FileProperties& fp, std::string& password, Contact* con)
{
    using namespace std;
    using namespace cppcrypto;
    using CryptoPP::Integer;
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

    vector<Exchange> exchanges; 
        
    // Bad code, in need of refactoring.   
    if(!con)
    {
        std::string anon("Anonymous");
        for(int i = 0; i < recipients.size(); i++)
        {
            Contact sender; 
            Integer priv = createContact(sender, recipients[i].dh, recipients[i].sp, anon, password);
            Integer p = a_exp_b_mod_c(recipients[i].person.publicKey, priv, recipients[i].dh.mod());
            Exchange ex(recipients[i].person, sender.person, recipients[i].sp, fp.cp, recipients[i].dh);
            ex.computed = p;
            exchanges.push_back(ex);
        }
    } 
    else
    {
        for(int i = 0; i < recipients.size(); i++)
        {
            Contact sender; 
            Integer priv = createContact(sender, recipients[i].dh, recipients[i].sp, con, password);
            Integer p = a_exp_b_mod_c(recipients[i].person.publicKey, priv, recipients[i].dh.mod());
            Exchange ex(recipients[i].person, sender.person, recipients[i].sp, fp.cp, recipients[i].dh);
            ex.computed = p;
            exchanges.push_back(ex);
        }
    }

    // Writes each of the exchanges.
    for(int i = 0; i < exchanges.size(); i++)
    {
        output = exchanges[i].out();
        len = (int16_t)output.length();

        // Write the exchange (EX)
        fo.write((char*)&len, sizeof(int16_t));
        fo.write(&output[0], len);
    }

    // Using the file's hash at the moment.
    std::string h = fp.hash;
    while(h.length() > blocksize) h.pop_back();
    unsigned char* iv = (unsigned char*)&h[0];

    int k = keysize + (blocksize - keysize % blocksize);
    unsigned char* ikey = (unsigned char*)&fp.key[0];

    for(int i = 0; i < exchanges.size(); i++)
    {
        string scr = intToScrypt(exchanges[i].computed, exchanges[i].sp, getCipherKeySize(fp.cp.cipherType), fp);
        const unsigned char* key = (unsigned char*)scr.c_str();

        ctr c(*bc);
        c.init(key, keysize, iv, blocksize);
    
        unsigned char *okey = new unsigned char[k]();

        for(int i = 0; i < keysize; i += blocksize)
        {
            c.encrypt(ikey + i, blocksize, okey + i);
        }

        fo.write((char*)okey, keysize);

        delete bc;
        getCipher(fp.cp.cipherType, bc);
        delete[] okey;
    }
    
    // Use the Key.
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

        std::string out("");
        
        // Writes each of the extensions
        for(int i = 0; i < extensions.size(); i++)
        {
            output = extensions[i].out();
            len = (int16_t)output.length();

            // Write the extensions
            out.append((char*)&len, sizeof(int16_t));
            out.append(&output[0], len);
        }

        // Writes out every full block
        while(out.length() > blocksize)
        {
            c2.encrypt((unsigned char*)&out[0], blocksize, (unsigned char*)outBuf);
            fo.write(outBuf, blocksize);
            out = out.substr(blocksize);
        }

        // This should work but we will see. 
        if(out.length())
        {
            for(int i = 0; i < out.length(); i++)
            {
                inBuf[i] = out[i];
            }

            // 16 >= 32 - 16
            if(fsize >= blocksize - out.length())
            {
                fi.read(inBuf + out.length(), blocksize - out.length());
                c2.encrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
                fo.write(outBuf, blocksize);
                fsize -= blocksize - out.length();
            }
            // 15 >= 32 - 16
            else
            {
                fi.read(inBuf + out.length(), fsize);
                c2.encrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
                fo.write(outBuf, out.length() + fsize);
                fsize = 0;
            }
        }


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
    delete[] inBuf;
    delete[] outBuf;
    fi.close();
    fo.close();
}


char decryptFile(const std::string& fileName, const std::string& outputFile, const std::vector<Exchange>& exchanges, std::vector<DataExtension>& extensions, const FileProperties& fp, const std::string& password, int person)
{
    using namespace std;
    using namespace cppcrypto;
    using CryptoPP::Integer;
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
    
    // Skip the exchanges
    for(int i = 0; i < exchanges.size(); i++)
    {
        fi.read(lenRead, sizeof(int16_t));
        len = *(int16_t*)lenRead;
        fi.ignore(len);

        fsize -= len;
        fsize -= sizeof(int16_t);
    }

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

    
    int k = keysize + (blocksize - keysize % blocksize);
    
    unsigned char* ikey = new unsigned char[k](), *okey = new unsigned char[k]();

    Exchange ex = exchanges[person/2];
    Integer pub; 
    string salt;
    if(person & 1)
    {
        // Bob
        salt = ex.bob.salt;
        pub = ex.alice.publicKey;
    }
    else
    {
        // Alice
        salt = ex.alice.salt;
        pub = ex.bob.publicKey;
    }

    Integer priv;
    string scr = getScrypt(password, salt, ex.sp.N, ex.sp.P, ex.sp.R, ex.sp.len);
    priv.Decode((unsigned char*)scr.c_str(), ex.sp.len);

    Integer p = a_exp_b_mod_c(pub, priv, ex.dh.mod());
    scr = intToScrypt(p, ex.sp, getCipherKeySize(fp.cp.cipherType), fp);
    unsigned char* key = (unsigned char*)scr.c_str();

    ctr c(*bc);
    c.init(key, keysize, iv, blocksize);


    // This will be the difficult part.
    for(int i = 0; i < exchanges.size(); i++)
    {
        if(i == (person/2)) fi.read((char*)ikey, keysize);
        else fi.ignore(keysize);
        fsize -= keysize;
    }

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
        int extracted = 0;
        int16_t left = -1;
        std::string out;
        std::string buf;

        while(fsize > blocksize)
        {
            fi.read(inBuf, blocksize);
            c2.decrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            mac.update((unsigned char*)outBuf, blocksize);

            // Hopefully this will work.
            if(extracted < fp.extensions)
            {
                buf.append(outBuf, blocksize);
                if(left == -1)
                {
                    left = *(int16_t*)&buf[0];
                }

                if(left + sizeof(int16_t) <= buf.length())
                {
                    out.append(&buf[0], left + sizeof(int16_t));
                    buf = buf.substr(left + sizeof(int16_t));
                    left = -1;
                    extracted++;
                }

                if(extracted == fp.extensions)
                {
                    fo.write(&buf[0], buf.length());    
                }
            }
            else
            {
                fo.write(outBuf, blocksize);
            }
            fsize -= blocksize;
        }

        if(fsize)
        {
            fi.read(inBuf, fsize);
            c2.decrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            mac.update((unsigned char*)outBuf, fsize);
            
            // Hopefully this will work.
            if(extracted < fp.extensions)
            {
                buf.append(outBuf, fsize);
                if(left == -1)
                {
                    left = *(int16_t*)&buf[0];
                }

                if(left + sizeof(int16_t) <= buf.length())
                {
                    out.append(&buf[0], left + sizeof(int16_t));
                    buf = buf.substr(left + sizeof(int16_t));
                    left = -1;
                    extracted++;
                }

                if(extracted == fp.extensions)
                {
                    fo.write(&buf[0], buf.length());    
                }
            }
            else
            {
                fo.write(outBuf, fsize);
            }
        }

        // Parses the Extensions
        DataExtension ex;
        int offset = 0;
        for(int i = 0; i < fp.extensions; i++)
        {
            len = *(int16_t*)&out[offset];
            offset += sizeof(int16_t);
            ex.parse(out, offset);
            extensions.push_back(ex);
            offset += len;
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


template void decodeFile<Contact>(Contact& c, const std::string& fileName);
template void decodeFile<DHParameters>(DHParameters& c, const std::string& fileName);
template void decodeFile<AsymmetricAuthenticationSignature>(AsymmetricAuthenticationSignature& c, const std::string& fileName);


template void encodeFile<Contact>(Contact& c, const std::string& fileName);
template void encodeFile<DHParameters>(DHParameters& c, const std::string& fileName);
template void encodeFile<AsymmetricAuthenticationSignature>(AsymmetricAuthenticationSignature& c, const std::string& fileName);
