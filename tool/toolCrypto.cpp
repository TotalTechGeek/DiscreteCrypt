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


// Uses an integer's data and the file's hmac to compute an Scrypt hash to a specified length.
std::string intToScrypt(const CryptoPP::Integer& i, const ScryptParameters& sp, int keyLen, const FileProperties& fp)
{
    unsigned char* dub1Out = new unsigned char[i.ByteCount()]();
    i.Encode(dub1Out, i.ByteCount());
    std::string pass("");
    pass.append((char*)dub1Out, i.ByteCount());
    delete[] dub1Out;
    return getScrypt(pass, fp.hash, sp.N, sp.P, sp.R, keyLen);
}

// Converts an integer to a raw string.
std::string cryptoIntToString(const CryptoPP::Integer& n)
{
    unsigned char* buf = new unsigned char[n.ByteCount()];
    n.Encode(buf, n.ByteCount());
    std::string res;
    res.append((char*)buf, n.ByteCount());
    delete[] buf;
    return res;
}

// Converts a raw string to an integer.
CryptoPP::Integer stringToCryptoInt(const std::string& s)
{
    CryptoPP::Integer res;
    res.Decode((unsigned char*)&s[0], s.length());
    return res;
}

// Computes a private key from the password, salt, and parameters.
CryptoPP::Integer passwordToPrivate(const std::string& pass, const std::string& salt, const ScryptParameters& sp)
{   
    std::string scr = getScrypt(pass, salt, sp.N, sp.P, sp.R, sp.len);
    CryptoPP::Integer priv;
    priv.Decode((unsigned char*)scr.c_str(), scr.length());
    return priv;
}
    

// Used to create a brand new contact
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

    CryptoPP::Integer priv = passwordToPrivate(password, salt, sp);
    CryptoPP::Integer pub = a_exp_b_mod_c(dh.gen(), priv, dh.mod());

    PersonParameters p(identity, salt, pub);
    
    con.person = p;
    con.sp = sp;
    con.dh = dh;

    return priv; 
}

// Used to create a contact with some existing parameters.
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

    CryptoPP::Integer priv = passwordToPrivate(password, salt, sp);
    CryptoPP::Integer pub = a_exp_b_mod_c(dh.gen(), priv, dh.mod());

    PersonParameters p(identity, salt, pub);
    con.person = p;
    con.sp = sp;
    con.dh = dh;

    return priv; 
}

// Used to generate a contact from an already existing contact, 
// This is sometimes necessary because another individual might be using another set of DHParameters.
CryptoPP::Integer createContact(Contact& con, const DHParameters& dh, const ScryptParameters& sp, Contact* contact, std::string& password)
{
    using namespace std;
  
    CryptoPP::Integer priv = passwordToPrivate(password, contact->person.salt, sp);
    CryptoPP::Integer pub = a_exp_b_mod_c(dh.gen(), priv, dh.mod());

    PersonParameters p(contact->person.identity, contact->person.salt, pub);
    con.person = p;
    con.sp = sp;
    con.dh = dh;

    return priv; 
}

// Gets the cipher's name.
std::string getCipherName(CipherType p)
{
    switch(p)
    {
        CIPHER_ENUM(MAKE_STRING) 
        default: return "";
    }
}

// Gets the cipher to decrypt with.
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

// Gets the hash function.
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

// Gets the hash's name.
std::string getHashName(HashType h)
{
    switch(h)
    {
        HASH_ENUM(MAKE_STRING)
        default:
        return "";
    }
}

// Gets the output size of the hash.
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

// Gets the size of the cipher's key.
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

// Gets the block size of the cipher.
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

// Writes an object to a file.
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

// Reads an object from a file.
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

// Decodes the encrypted file. (Unencrypted Segments)
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

// Pad an HMAC with random data if the hmac is less than the block size.
// This is necessary for when the hash output size is less than the block size of the cipher.
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


// Computes an hmac for a file.
void hmacFile(const std::string& filename, const std::vector<DataExtension>& extensions, FileProperties& fp)
{
    using namespace cppcrypto;
    using namespace std;

    // Establish a key.
    int keySize = getCipherKeySize(fp.cp.cipherType) / 8;
    int blockSize = getCipherBlockSize(fp.cp.cipherType) / 8;
    createFileKey(fp);

    // Sets the extension count.
    fp.extensions = extensions.size();

    unsigned char* hash;
    crypto_hash* bc;
    
    // Gets the hash function for the hmac
    getHash(fp.ht, bc);

    hmac mac(*bc, (unsigned char*)fp.key.c_str(), keySize);
    mac.init();

    // Include the extension count in the hash.
    // this is a File v3 Format adjustment. 
    // All the other parameters don't need to be included due to the fact that they're
    // integral to the decryption process.
    mac.update((unsigned char*)&fp.extensions, sizeof(fp.extensions));

    // Hashes each of the extensions.
    for(int i = 0; i < extensions.size(); i++)
    {
        string output = extensions[i].out();
        int16_t len = (int16_t)output.length();

        // Write the extensions to the hmac
        mac.update((unsigned char*)&len, sizeof(int16_t));
        mac.update((unsigned char*)&output[0], len);
    }

    // opens the file to hmac
    ifstream fi(filename, ios::binary);
    
    hash = new unsigned char[bc->hashsize() / 8]();
    int x = bc->blocksize() / 8;
    if(x == 0) x = bc->hashsize() / 8;

    char* block = new char[x]();

    // Reads in the entire file and hashes it.
    if(fi.good())
    {
        // Gets the file size 
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
    
    // Set the FP's hmac.
    fp.hash = "";
    fp.hash.append((char*)hash, bc->hashsize() / 8);
    fp.hash = hashPad(fp.hash, blockSize);

    fi.close();
    delete[] block;
    delete[] hash;
    delete bc;
}


// Exports a file bundled with its signature
void bundleFile(const std::string& fileName, const std::string& outputFile, const Contact& sender, const std::string& password, HashType hashType)
{
    using namespace std;
    AsymmetricAuthenticationSignature aas(sender, fileName, password, hashType);

    string out; 
    out = aas.out();
    int16_t len = out.length();

    // Write the signature
    ofstream outFile(outputFile, ios::binary);
    outFile.write((char*)&len, sizeof(int16_t));
    outFile.write(&out[0], out.length());


    ifstream inFile(fileName, ios::binary);

    char buf[1];

    // This is a quick hack to write the file out.
    inFile.read(buf, 1);
    while(!inFile.eof())
    {
        outFile.write(buf, 1);
        inFile.read(buf, 1);
    }

    inFile.close();
    outFile.close();
}

// Extracts the file from a signature bundle and verifies it.
AsymmetricAuthenticationSignature debundleFile(const std::string& fileName, const std::string& outputFile)
{
    using namespace std;
    char lenIn[2];
    char buf[1];
    int16_t len;

    ifstream file(fileName, ios::binary);
    ofstream ofile(outputFile, ios::binary);
    file.read(lenIn, 2);

    len = *(int16_t*)&lenIn;

    char *block = new char[len];
    file.read(block, len);
    string in("");
    in.append(block, len);

    AsymmetricAuthenticationSignature aas;
    aas.parse(in);

    // Quick hack to write the file out.
    file.read(buf, 1);
    while(!file.eof())
    {
        ofile.write(buf, 1);
        file.read(buf, 1);
    }

    ofile.close();
    file.close();

    
    delete[] block;
    return aas;
}


// Encrypts a file.
void encryptFile(const std::string& fileName, const std::string& outputFile, const std::vector<Contact>& recipients, const std::vector<DataExtension>& extensions, const FileProperties& fp, std::string& password, Contact* con)
{
    using namespace std;
    using namespace cppcrypto;
    using CryptoPP::Integer;

    // Opens the files.
    ifstream fi(fileName, ios::binary);
    ofstream fo(outputFile, ios::binary);

    // Gets the block cipher to encrypt the key with.
    block_cipher *bc;
    getCipher(fp.cp.cipherType, bc);

    // Grabs the block size and key size for the cipher.
    // Divisible by 8 because we're actually getting byte size (as opposed to bit size).
    int blocksize = (int)bc->blocksize() / 8;
    int keysize = (int)bc->keysize() / 8;

    // Gets the file parameters output data.
    string output = fp.out();
    int16_t len = (int16_t)output.length();


    // Write the header (FP)
    fo.write((char*)&len, sizeof(int16_t));
    fo.write(&output[0], len);


    // List of exchanges to be computed from the contacts
    vector<Exchange> exchanges; 
        
    // Bad code, in need of refactoring.   
    if(!con)
    {
        // Creates an anonymous contact for each of the recipients, then computes an exchange for each of them.
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
        // Creates (or clones) the input contact for each of the recipients, and computes an exchange for each of them.
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

    // Grab the file's hmac.
    std::string h = fp.hash;

    // If the hmac is longer than the file's block size, truncate.
    while(h.length() > blocksize) h.pop_back();

    // Create an initialization vector from the hmac.
    unsigned char* iv = (unsigned char*)&h[0];

    // The size of the buffer used to encrypt the key with.
    // Computed in this way to make it divisible by the block size.
    int k = keysize + (blocksize - keysize % blocksize);
    
    // Points to the key to encrypt the payload with.
    unsigned char* ikey = (unsigned char*)&fp.key[0];

    // For each of the exchanges, encrypt the key used for payload encryption.
    for(int i = 0; i < exchanges.size(); i++)
    {
        // Derives a key from the exchange to encrypt the payload key with. 
        string scr = intToScrypt(exchanges[i].computed, exchanges[i].sp, getCipherKeySize(fp.cp.cipherType), fp);
        const unsigned char* key = (unsigned char*)scr.c_str();

        // Sets up a block cipher using the exchange key to encrypt the payload key.
        ctr c(*bc);
        c.init(key, keysize, iv, blocksize);
    
        // Output buffer for encryption.
        unsigned char *okey = new unsigned char[k]();

        // Encrypts the key (fully).
        for(int i = 0; i < keysize; i += blocksize)
        {
            c.encrypt(ikey + i, blocksize, okey + i);
        }

        // Writes the encrypted key to a file.
        fo.write((char*)okey, keysize);

        // Establishes a new block cipher.
        delete bc;
        getCipher(fp.cp.cipherType, bc);
        delete[] okey;
    }
    
    // Sets up a new block cipher using the Payload Key.
    ctr c2(*bc);
    c2.init(ikey, keysize, iv, blocksize);
    

    // Gets the file size
    int fsize = 0;
    fi.seekg(0, ios::end);
    fsize = (int)fi.tellg() - fsize;
    fi.seekg(0, ios::beg);


    // Sets up the file buffers.
    char* inBuf = new char[blocksize];
    char* outBuf = new char[blocksize];

    // Tests the file
    if(fi.good() && !fi.bad())
    {

        std::string out("");
        
        // Exports each of the extensions
        for(int i = 0; i < extensions.size(); i++)
        {
            output = extensions[i].out();
            len = (int16_t)output.length();

            // Write the extensions
            out.append((char*)&len, sizeof(int16_t));
            out.append(&output[0], len);
        }

        // Writes out every full block of extension data.
        while(out.length() > blocksize)
        {
            c2.encrypt((unsigned char*)&out[0], blocksize, (unsigned char*)outBuf);
            fo.write(outBuf, blocksize);
            out = out.substr(blocksize);
        }

        // If there is still extension data
        if(out.length())
        {
            // Populate the "to-encrypt" buffer
            for(int i = 0; i < out.length(); i++)
            {
                inBuf[i] = out[i];
            }

            // If there is more than enough file data to fill the rest of the buffer
            // 16 >= 32 - 16
            if(fsize >= blocksize - out.length())
            {
                fi.read(inBuf + out.length(), blocksize - out.length());
                c2.encrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
                fo.write(outBuf, blocksize);
                fsize -= blocksize - out.length();
            }
            // 15 >= 32 - 16
            // otherwise, fill the rest of the buffer with the remaining file data.
            else
            {
                fi.read(inBuf + out.length(), fsize);
                c2.encrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
                fo.write(outBuf, out.length() + fsize);
                fsize = 0;
            }
        }

        // While there is enough file data to encrypt a whole block
        while(fsize > blocksize)
        {
            fi.read(inBuf, blocksize);
            c2.encrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            fo.write(outBuf, blocksize);
            fsize -= blocksize;
        }

        // Encrypt any remaining data.
        if(fsize)
        {
            fi.read(inBuf, fsize);
            c2.encrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            fo.write(outBuf, fsize);
        }
    }

    // cleanup
    delete bc;
    delete[] inBuf;
    delete[] outBuf;

    // close files
    fi.close();
    fo.close();
}


// Decrypts a file.
char decryptFile(const std::string& fileName, const std::string& outputFile, const std::vector<Exchange>& exchanges, std::vector<DataExtension>& extensions, const FileProperties& fp, const std::string& password, int person)
{
    using namespace std;
    using namespace cppcrypto;
    using CryptoPP::Integer;

    // Open the files.
    ifstream fi(fileName, ios::binary);
    ofstream fo(outputFile, ios::binary);

    // Gets the file size (hopefully)
    int fsize = 0;
    fi.seekg(0, ios::end);
    fsize = (int)fi.tellg() - fsize;
    fi.seekg(0, ios::beg);

    char lenRead[sizeof(int16_t)];

    // Used to skip the FP Header.
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


    // Sets up block cipher and hash algorithm.
    block_cipher *bc;
    crypto_hash *hc; 
    getHash(fp.ht, hc);
    getCipher(fp.cp.cipherType, bc);

    // Sets up the hash output.
    unsigned char* hash = new unsigned char[hc->hashsize() / 8];
    
    // Gets the byte size of the cipher's block and key sizes.
    int blocksize = (int)bc->blocksize() / 8;
    int keysize = (int)bc->keysize() / 8;

    // Gets the file's hmac
    std::string h = fp.hash;

    // Truncates the hmac if it is greater than the cipher's key size.
    while(h.length() > blocksize) h.pop_back();

    // Use the hmac as an initialization vector.
    unsigned char* iv = (unsigned char*)&h[0];

    // Sets up the decryption buffers.
    char* inBuf = new char[blocksize];
    char* outBuf = new char[blocksize];

    // k value used to decrypt the key evenly with the block size
    int k = keysize + (blocksize - keysize % blocksize);
    
    // key decryption buffers
    unsigned char* ikey = new unsigned char[k](), *okey = new unsigned char[k]();

    // Grabs the public key from the selected exchange. 
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

    // Computes the private key for the person that is decrypting
    Integer priv = passwordToPrivate(password, salt, ex.sp);
    
    // Computes the exchange
    Integer p = a_exp_b_mod_c(pub, priv, ex.dh.mod());

    // Derives the decryption key from the exchange.
    string scr = intToScrypt(p, ex.sp, getCipherKeySize(fp.cp.cipherType), fp);
    unsigned char* key = (unsigned char*)scr.c_str();

    // Use the exchange's decryption key to establish a set up a block cipher.
    ctr c(*bc);
    c.init(key, keysize, iv, blocksize);


    // Read in the selected key, and ignore the others.
    for(int i = 0; i < exchanges.size(); i++)
    {
        if(i == (person/2)) fi.read((char*)ikey, keysize);
        else fi.ignore(keysize);
        fsize -= keysize;
    }

    // Decrypts the payload key.
    for(int i = 0; i < keysize; i += blocksize)
    {
        c.decrypt(ikey + i, blocksize, okey + i);
    }

    // Delete the block cipher.
    delete bc;

    // Sets up the payload authenticator 
    hmac mac(*hc, okey, keysize);
    mac.init();

    // Used for checking the number of extensions.
    // This will soon be mandatory. (No if-statement required)
    if(fp.version >= 3)
    {
        mac.update((unsigned char*)&fp.extensions, sizeof(fp.extensions));
    }
    
    // Establish the payload key.
    getCipher(fp.cp.cipherType, bc);
    ctr c2(*bc);
    c2.init(okey, keysize, iv, blocksize);

    // File test
    if(fi.good() && !fi.bad())
    {
        int extracted = 0;
        int16_t left = -1;
        std::string out;
        std::string buf;

        // While there are full blocks to decrypt
        while(fsize > blocksize)
        {
            // Read in the block, decrypt it, and add it to the hmac.
            fi.read(inBuf, blocksize);
            c2.decrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            mac.update((unsigned char*)outBuf, blocksize);

            // If there is still data to extract as an extension,
            if(extracted < fp.extensions)
            {
                // append it to the extension buffer
                buf.append(outBuf, blocksize);

                // if the extension length hasn't been parsed,
                if(left == -1)
                {
                    // parse the extension length
                    left = *(int16_t*)&buf[0];
                }

                // If we have enough of the data to parse into an extension,
                if(left + sizeof(int16_t) <= buf.length())
                {
                    // remove it from the buffer, then increment the number of extensions read.
                    out.append(&buf[0], left + sizeof(int16_t));
                    buf = buf.substr(left + sizeof(int16_t));
                    left = -1;
                    extracted++;
                }

                // If we've read in all of the extensions, just write the remaining data in the buffer to the output file.
                if(extracted == fp.extensions)
                {
                    fo.write(&buf[0], buf.length());
                }
            }
            else
            {
                // Write the full block to the output file.
                fo.write(outBuf, blocksize);
            }

            // Removes an entire block size from the fsize remaining.
            fsize -= blocksize;
        }

        // If there is still more data to decrypt
        if(fsize)
        {
            // Read in the data left, decrypt it, and add it to the hmac.
            fi.read(inBuf, fsize);
            c2.decrypt((unsigned char*)inBuf, blocksize, (unsigned char*)outBuf);
            mac.update((unsigned char*)outBuf, fsize);
            
            // If there are extensions to extract, 
            if(extracted < fp.extensions)
            {
                // append it to an extension buffer
                buf.append(outBuf, fsize);

                // if the extension length hasn't been parsed,
                if(left == -1)
                {
                    // parse the extension length
                    left = *(int16_t*)&buf[0];
                }

                 // If we have enough of the data to parse into an extension,
                if(left + sizeof(int16_t) <= buf.length())
                {
                    // remove it from the buffer, then increment the number of extensions read.
                    out.append(&buf[0], left + sizeof(int16_t));
                    buf = buf.substr(left + sizeof(int16_t));
                    left = -1;
                    extracted++;
                }

                 // If we've read in all of the extensions, just write the remaining data in the buffer to the output file.
                if(extracted == fp.extensions)
                {
                    fo.write(&buf[0], buf.length()); 
                }
            }
            else
            {
                // Write the rest of the data to the output file.
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


    // Outputs the hmac
    mac.final(hash);
    char valid = 1;

    // Compares the hmacs.
    for(int i = 0; i < hc->hashsize() / 8; i++)
    {
        valid = valid && hash[i] == (unsigned char)fp.hash[i];
    }


    // Cleanup
    delete hc;
    delete bc;
    delete[] ikey;
    delete[] okey;
    delete[] hash;
    delete[] inBuf;
    delete[] outBuf;

    // Closes the file.
    fi.close();
    fo.close();

    return valid;
}


// Template function declarations.
template void decodeFile<Contact>(Contact& c, const std::string& fileName);
template void decodeFile<DHParameters>(DHParameters& c, const std::string& fileName);
template void decodeFile<AsymmetricAuthenticationSignature>(AsymmetricAuthenticationSignature& c, const std::string& fileName);


template void encodeFile<Contact>(Contact& c, const std::string& fileName);
template void encodeFile<DHParameters>(DHParameters& c, const std::string& fileName);
template void encodeFile<AsymmetricAuthenticationSignature>(AsymmetricAuthenticationSignature& c, const std::string& fileName);
