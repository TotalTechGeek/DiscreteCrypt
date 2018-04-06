#include <array>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
#include <sstream>
#include <tuple>
#include <assert.h>

#include "../cryptopp/osrng.h"
#include "../cryptopp/integer.h"
#include "../cryptopp/nbtheory.h"

#include "AsymmetricAuthenticationExtension.h"
#include "SymmetricAuthenticationExtension.h"
#include "Parameters.h"
#include "toolCrypto.h"

using namespace std;
using CryptoPP::Integer;
using CryptoPP::OS_GenerateRandomBlock;

struct ProgramParams
{
    ScryptParameters sp;
    CipherParams cp;
    
    HashType h = HashType::SHA256;
    DHParameters dh = DHParameters("2", "1236027852723267358067496240415081192016632901798652377386974104662393263762300791015297301419782476103015366958792837873764932552461292791165884073898812814414137342163134112441573878695866548152604326906481241134560091096795607547486746060322717834549300353793656273878542405925895784382400028374603183267116520399667622873636417533621785188753096887486165751218947390793886174932206305484313257628695734926449809428884085464402485504798782585345665225579018127843073619788513405272670558284073983759985451287742892999484270521626583252756445695489268987027078838378407733148367649564107237496006094048593708959670063677802988307113944522310326616125731276572628521088574537964296697257866765026848588469121515995674723869067535040253689232576404893685613618463095967906841853447414047313021676108205138971649482561844148237707440562831931089544088821151806962538015278155763187487878945694840272084274212918033049841007502061");
    
    string from;
    string exportSigners;

    bool force = false;

    vector<string> messages;
    vector<tuple<string, string>> symmetricAuthentications;
};

namespace StringSplitFunctions
{
	//Not the most efficient but decent implementations for a competitition.

	//Replaces part of the string with another string.
	//Pass in the original, and the delimiter.
	//Replaces delimiter with the 'replaceWith' parameter.
	void replacePart(string& original, string delim, string replaceWith)
	{
		while (original.find(delim) != -1)
		{
			original.replace(original.find(delim), delim.size(), replaceWith);
		}
	}


	//splits the string and puts it in a vector to be returned :).
	//using this to split up the commas on the lines.
	void splitString(vector<string>& returner, string str, string delim, char op = 0)
	{
		string op2("");
		op2 += op;
		replacePart(str, delim, op2);
		istringstream stream(str);

		while (stream)
		{
			string n;

			getline(stream, n, op);

			if (n.size() == 0 || (n[0] == 0 && n.size() == 1)) //avoids returning empty strings.
			{
				//nothing
			}
			else
			{
				//something.
				returner.push_back(n);
			}
		}


	}
}

void dhtest(ProgramParams& programParams)
{
    CryptoPP::AutoSeededRandomPool rnd;
    cout << programParams.dh.mod() << " (" << programParams.dh.mod().BitCount() << ")" << endl;
    bool mod = IsPrime(programParams.dh.mod()) && RabinMillerTest(rnd, programParams.dh.mod(), 3); 
    cout << (mod ? "Valid" : "Invalid") << endl;
    Integer m = programParams.dh.mod() - 1;
    for(int i = 2; i < 65536; i++)
    {
        while(!(m % i) && (m != i)) m /= i;
    }
    cout << programParams.dh.gen() << endl << endl;
    cout << m << " (" << m.BitCount() << ")" << endl;
    bool poh = IsPrime(m) && RabinMillerTest(rnd, m, 3);
    cout << (poh ? "Valid" : "Invalid") << endl;
    cout << endl;
    cout << ((poh&&mod) ? "Verified" : "Bad Parameters") << endl;
}

void verify(ProgramParams& programParams, const string& sig, const string& file)
{
    AsymmetricAuthenticationSignature aas;
    decodeFile(aas, sig);

    // Export the signer.
    if(programParams.exportSigners.length())
    {
        Contact c(aas.contact());
        encodeFile(c, programParams.exportSigners);
    }

    cout << "Signed by: " << aas.contact().person.identity << endl << "UID: 0x" << aas.contact().uidHex() << endl;
    cout << "Hash Algorithm: " << getHashName(aas.hashType()) << endl;
    cout << (aas.verify(file) ? "Signature Verified" : "Signature Verification Failed") << endl;
}

void to(ProgramParams& programParams, const string& contact, const string& file, const string& ofile, bool cli = false)
{
    string password("");
    vector<Contact> recipients;
    vector<DataExtension> extensions;
    vector<string> recipients_s;
    
    Contact fromCon;
    Contact* con = 0;
    
    FileProperties fp(programParams.cp, programParams.h);

    StringSplitFunctions::splitString(recipients_s, contact, ",");
    for(int i = 0; i < recipients_s.size(); i++)
    {
        Contact recipient;
        if(!cli) recipients_s[i].append(".contact");
        decodeFile(recipient, recipients_s[i]);
        recipients.push_back(recipient);
    }
        
    // bad debug command to test sending "from"
    if(programParams.from.length())
    {
        cout << "Password for " << programParams.from << ": ";
        password = getPassword();
        decodeFile(fromCon, programParams.from);
        con = &fromCon;               
    }

    vector<Exchange> exchanges = createExchanges(recipients, fp, password, con);

    for(int i = 0; i < programParams.symmetricAuthentications.size(); i++)
    {
        string message, answer;
        tie(message, answer) = programParams.symmetricAuthentications[i];
        SymmetricAuthenticationExtension sae(message, answer, file, programParams.h);
        extensions.push_back(sae.out());
    }

    for(int i = 0; i < programParams.messages.size(); i++)
    {
        DataExtension de; 
        de.et = ExtensionType::MESSAGE;
        de.data = programParams.messages[i];
        extensions.push_back(de);
    }

    if(con)
    {
        AsymmetricAuthenticationExtension aae(fromCon, file, password, programParams.h);
        extensions.push_back(aae.outData());

        // Silly test, needs to be split into different code.
        for(int i = 0; i < exchanges.size(); i++)
        {
            auto uid = exchanges[i].bobContact().uid(programParams.h);
            if(uid != con->uid(programParams.h))
            {
                AsymmetricAuthenticationExtension authorization(*con, aae.out() + "AUTH" + uid, password, programParams.h, true);
                DataExtension authDE = authorization.outData();
                authDE.et = ExtensionType::AUTHORIZATION;
                authDE.data = uid + authDE.data;
                extensions.push_back(authDE);
            }
        }
        

    }
    
    hmacFile(file, extensions, fp);
    encryptFile(file, ofile, exchanges, extensions, fp, password);
}

void ciphlist()
{
    for(int i = 0; i < sizeof(AVAILABLE_CIPHERS_CODES) / sizeof(int16_t); i++)
    {
        cout << AVAILABLE_CIPHERS[i] << " - " << std::oct << AVAILABLE_CIPHERS_CODES[i] << endl;
    }
    cout << std::dec;
}

void hashlist()
{
    for(int i = 0; i < sizeof(AVAILABLE_HASHES_CODES) / sizeof(uint16_t); i++)
    {
        cout << AVAILABLE_HASHES[i] << " - " << std::oct << AVAILABLE_HASHES_CODES[i] << endl;
        cout << std::dec;
    }   
}

void previewEncrypted(ProgramParams& programParams, const string& file)
{
    Exchange ex;
    FileProperties fp(programParams.cp, programParams.h);
    vector<Exchange> exchanges;
    decodeEncrypted(exchanges, fp, file);
    cout << "File Format Version: " << (int)fp.version << endl << endl;
    cout << "People: " << endl;
    for(int i = 0; i < exchanges.size(); i++)
    {
        cout << exchanges[i].alice.identity << " (0x" << exchanges[i].aliceContact().uidHex() << ")" << endl
        << exchanges[i].bob.identity << " (0x" << exchanges[i].bobContact().uidHex() << ")" << endl;
    }
    cout << endl;
    cout << "Cipher: " << getCipherName(fp.cp.cipherType) << endl << "Hash: " << getHashName(fp.ht) << endl << endl;
    
    cout << "Extension count: " << fp.extensions << endl;
}

void previewContact(const string& contactFile)
{
    Contact con;
    decodeFile(con, contactFile);

    cout << "Identity: " << con.person.identity << endl
         << "Salt: 0x" << con.person.saltHex() << endl
         << "Public Key: " << con.person.publicKey << endl
         << "UID: 0x" << con.uidHex() << endl;

    cout << endl;
    cout << "Generator: " << con.dh.gen() << endl
         << "Modulus: " << con.dh.mod() << " (" << con.dh.mod().BitCount() << ")" << endl;
}

void help()
{
    cout << "-contact <output file>" << "\t\t\t\t" << "Creates a contact." << endl;
    cout << "-to <contact files> <input file> <output file>" << "\t" << "Encrypts file for a contact." << endl;
    cout << "-open <file> <output file>" << "\t\t\t" << "Opens a file" << endl;
    cout << "-check <contact file>" << "\t\t\t\t" << "Checks if password matches a contact file." << endl;
    cout << "-ciph <ciph #>" << "\t\t\t\t\t" << "Sets the ciph used." << endl;
    cout << "-ciphlist" << "\t\t\t\t\t" << "Prints out all the ciphers available." << endl;
    cout << "-hash <hash #>" << "\t\t\t\t\t" << "Sets the hash used." << endl;
    cout << "-hashlist" << "\t\t\t\t\t" << "Prints out all the hash functions available." << endl;
    cout << "-ldh <dh file>" << "\t\t\t\t\t" << "Loads discrete log parameters from a file." << endl;
    cout << "-from <contact file>" << "\t\t\t\t" << "Sets which contact files are from." << endl;
    cout << "-sign <contact file> <in file> <out file>" << "\t" << "Signs a file using a contact." << endl;
    cout << "-bundle <contact file> <in file> <out file>" << "\t" << "Signs a file using a contact, and creates a bundle from them." << endl;
    cout << "-debundle <bundle file> <out file>" << "\t\t" << "Verifies a file's signature, and exports the original file from the bundle." << endl;
    cout << "-verify <sig file> <out file>" << "\t\t\t" << "Verifies a file from its signature." << endl;
    
    cout << "-pdh" << "\t\t\t\t\t\t" << "Prints discrete log parameters." << endl;
    cout << "-pldh" << "\t\t\t\t\t\t" << "Prints discrete log parameters from file." << endl;
    cout << "-dhtest" << "\t\t\t\t\t\t" << "Tests the currently loaded parameters." << endl;


    cout << "-pc <contact file>" << "\t\t\t\t" << "Prints contact information." << endl;
    cout << "-pe <encrypted file>" << "\t\t\t\t" << "Prints encrypted file information." << endl;
    cout << "------" << endl;
    cout << "--prompt[-hidden] <question>" << "\t" << "Allows you to add an OTR-Style prompt for symmetric authentication." << endl;
    cout << "--add-message[-hidden]" << "\t" << "Allows you to add a message to output during the decryption process" << endl;
    cout << "--exportSigners <out>" << "\t" << "If an encrypted file is asymmetrically signed, this parameter will export its signers." << endl;
    cout << "--drop" << "\t" << "Drops all messages and OTR prompts." << endl;
    cout << "-exdhc <contact file> <out>" << "\t" << "Extracts DH Parameters from a contact file." << endl;
    cout << "-exdhe <contact file> <out>" << "\t" << "Extracts DH Parameters from an encrypted file." << endl;
    cout << "-exc <encrypted file> <out contact file>" << "\t" << "Extracts a contact from an encrypted file." << endl;
}



void authorizations(const FileProperties& fp, const vector<DataExtension>& extensions, const vector<Exchange>& exchanges)
{
    int first = 0;
    AsymmetricAuthenticationExtension signer;

    for(int i = 0; i < extensions.size(); i++)
    {
        if(extensions[i].et == ExtensionType::ASYMMETRIC)
        {
            signer.parse(extensions[i]);
        }
        if(extensions[i].et == ExtensionType::AUTHORIZATION)
        {
            if(!(first++)) cout << "=== Authorizations ===" << endl;
            int outSize = getHashOutputSize(fp.ht) / 8;
            string toAuthorize = extensions[i].data.substr(0, outSize);
            
            DataExtension de;
            
            de.data = extensions[i].data.substr(outSize);
            AsymmetricAuthenticationExtension aae(de);
            cout << (aae.contact().person.identity) << " (0x" << aae.contact().uidHex() << ")" << endl;
            
            // Because the uid is typically shown as its SHA256 representation.
            for(int j = 0; j < exchanges.size(); j++)
            {
                if(exchanges[j].aliceContact().uid(fp.ht) == toAuthorize)
                {
                    cout << "Authorizing: 0x" << exchanges[j].aliceContact().uidHex() << endl;
                    break;
                }
                else if(exchanges[j].bobContact().uid(fp.ht) == toAuthorize)
                {
                    cout << "Authorizing: 0x" << exchanges[j].bobContact().uidHex() << endl;
                    break;
                }
            }
            
            cout << (aae.verify(signer.out() + "AUTH" + toAuthorize, fp.ht, true) ? "Success" : "Fail") << endl;
        }
    }

    if(first) cout << "=== End Authorizations ===" << endl;
}

void symmetricCheck(ProgramParams& programParams, const FileProperties& fp, const vector<DataExtension>& extensions, const std::string& ofile)
{
    int first = 0;
    for(int i = 0; i < extensions.size(); i++)
    {
        if(extensions[i].et == ExtensionType::SYMMETRIC)
        {
            if(!(first++))
            {
                cout << "=== Symmetric Authentication ===" << endl;
            }
            SymmetricAuthenticationExtension sae(extensions[i]);
            cout << sae.prompt() << endl;
            string command = getPassword();
            cout << (sae.check(command, ofile, fp.ht) ? "Success" : "Fail") << endl;                 
        }
    }

    if(first) cout << "=== End Symmetric Authentication ===" << endl;
}

void messagesShow(const vector<DataExtension>& extensions)
{
    int first = 0;

    for(int i = 0; i < extensions.size(); i++)
    {
        if(extensions[i].et == ExtensionType::MESSAGE)
        {
            if(!(first++))
            {
                cout << "=== Messages ===" << endl;
            }
            cout << extensions[i].data << endl;
        }
    }
    if(first) cout << "=== End Messages ===" << endl;
}


void asymmetricCheck(ProgramParams& programParams, const FileProperties& fp, const vector<DataExtension>& extensions, const std::string& ofile)
{
    int moreThanOne = 0, first = 0;
    for(int i = 0; i < extensions.size(); i++)
    {
        if(extensions[i].et == ExtensionType::ASYMMETRIC)
        {
            if(!(first++))
            {
                cout << "=== Asymmetric Authentication ===" << endl;
            }
            AsymmetricAuthenticationExtension aae(extensions[i]);
            cout << (aae.contact().person.identity) << " (0x" << aae.contact().uidHex() << ")" << endl;
            cout << (aae.verify(ofile, fp.ht) ? "Success" : "Fail") << endl;
            // Allows someone to export the signers of a message.
            if(programParams.exportSigners.length())
            {
                Contact con(aae.contact());
                if(moreThanOne++)
                {
                    // If there's more than one signer / author, export them separately.
                    encodeFile(con, to_string(moreThanOne) + "_" + programParams.exportSigners);
                }
                else
                {
                    encodeFile(con, programParams.exportSigners);
                }
            }
        }
    }

    if(first) cout << "=== End Asymmetric Authentication ===" << endl;
}


void open(ProgramParams& programParams, const string& file, const string& ofile)
{
    string password, command;
    int person;
    
    FileProperties fp(programParams.cp, programParams.h);
    vector<Exchange> exchanges;
    vector<DataExtension> extensions;
    decodeEncrypted(exchanges, fp, file);
    
    // File version check code.
    if(fp.version < DISCRETECRYPT_FILE_VERSION)
    {
        cout << "Warning: Decrypting an old file format." << endl;
        if(fp.version == 2)
        {
            if(programParams.force);
            else
            {
                cout << "Error: Refusing to decrypt old file version. Use --force." << endl;
                cout << "Warning: This version will not be supported for much longer." << endl;
                return;
            }
        }
        else
        {
            cout << "Error: Can't decrypt file." << endl;
            return;
        }
    }
    else
    if(fp.version > DISCRETECRYPT_FILE_VERSION)
    {
        cout << "Warning: May not be able to decrypt newer file version." << endl;
    }

    for(int i = 0; i < exchanges.size(); i++)
    {
        cout << (i*2+1) << ") " << exchanges[i].alice.identity << " (0x" << exchanges[i].aliceContact().uidHex() << ")" << endl
        << (i*2+2) << ") " << exchanges[i].bob.identity << " (0x" << exchanges[i].bobContact().uidHex() << ")" << endl;
    }

    getline(cin, command);
    person = stoi(command) - 1;
    cout << "Password: ";
    password = getPassword();
    bool success = decryptFile(file, ofile, exchanges, extensions, fp, password, person);
    cout << (success ? "Success" : "Fail") << endl;
    
    if(success)
    {
        messagesShow(extensions);
        symmetricCheck(programParams, fp, extensions, ofile);
        asymmetricCheck(programParams, fp, extensions, ofile);
        authorizations(fp, extensions, exchanges);
    }
    
}

void sign(ProgramParams& programParams, const string& from, const string& file, const string& ofile)
{
    string password;
    Contact con;
    decodeFile(con, from);
    
    cout << "Password: ";
    password = getPassword();
    
    if(con.verify(password))
    {
        AsymmetricAuthenticationSignature aas(con, file, password, programParams.h);
        encodeFile(aas, ofile);
    }
}

void extractContact(ProgramParams& programParams, const string& in, const string& out)
{
    string command;

    vector<Exchange> exchanges;
    FileProperties fp(programParams.cp, programParams.h);
    decodeEncrypted(exchanges, fp, in);
    Exchange ex;
    
    for(int i = 0; i < exchanges.size(); i++)
    {
        ex = exchanges[i];
        cout    << (i*2+1) << ") " << ex.alice.identity << " (0x" << ex.aliceContact().uidHex() << ")" << endl 
                << (i*2+2) << ") " << ex.bob.identity << " (0x" << ex.bobContact().uidHex() << ")" << endl;
    }

    getline(cin, command);
    int person = stoi(command) - 1;
    ex = exchanges[person/2];
    Contact c;
    if(person & 1)
    {
        c = ex.bobContact();  
    }
    else
    {
        c = ex.aliceContact();
    }
    encodeFile(c, out);
}

void ciph(ProgramParams& programParams, const string& ciph)
{
    programParams.cp.cipherType = (CipherType)stoi(ciph, 0, 8);
    cout << getCipherName(programParams.cp.cipherType) << endl; 
}

void hashCommand(ProgramParams& programParams, const string& hash)
{
    programParams.h = (HashType)stoi(hash, 0, 8);
    cout << getHashName(programParams.h) << endl;
}

void contact(ProgramParams& programParams, const string& outfile)
{
    string command;
    Contact con;
    createContact(con, programParams.dh, programParams.sp);
    command.append(".contact");
    encodeFile(con, outfile);
}

void checkContact(ProgramParams& programParams, const string& contactFile)
{
    Contact con;
    decodeFile(con, contactFile);
    cout << "Password: "; 
    string password = getPassword();
    bool verified = con.verify(password);
    cout << (verified ? "Verified" : "Not Verified")  << endl;
}

DHParameters extractDHParameters_e(const string& file)
{
    string command;
    
    FileProperties fp(CipherParams(), HashType::SHA256);
    vector<Exchange> exchanges;
    decodeEncrypted(exchanges, fp, file);
                
    for(int i = 0; i < exchanges.size(); i++)
    {
        cout << (i+1) << ") " << exchanges[i].dh.mod() << " (" << exchanges[i].dh.mod().BitCount() << ")" << endl; 
    }

    getline(cin, command);

    return exchanges[stoi(command) - 1].dh;
}

DHParameters extractDHParameters_c(const string& file)
{
    Contact con;
    decodeFile(con, file);
    return con.dh;
}

void pdh(const DHParameters & dh)
{
    Integer pohlig, factors;
    cout << dh.gen() << endl << endl;
    cout << dh.mod() << " (" << dh.mod().BitCount() << ")" << endl;
    cout << endl;
    tie(pohlig, factors) = dh.pohlig();
    cout << pohlig << " (" << pohlig.BitCount() << ")" << endl;
}

// Todo: Provide a method of allowing a person to "claim" a new fingerprint, both in an encrypted file and in a separate format.
// Todo: Create a lightweight C++ API and migrate some of the current code to be more OO friendly. 
// Todo: Provide new constructs to be able to define concepts like "protocols". This will allow codebases to employ concepts like "trust". 

// The identity field will eventually use JSON.
int main(int argc, char**args)
{
    string command;
    ProgramParams programParams;

    if(argc >= 2)
    {
        // CLI 
        for(int i = 1; i < argc; i++)
        {
            string cur(args[i]);
            if(cur[0] == '-')
            {
                cur = cur.substr(1);
                if(cur == "ciph")
                {
                    ciph(programParams, string(args[++i]));
                }
                else if(cur == "hash")
                {
                    hashCommand(programParams, string(args[++i]));
                }
                else if(cur == "hashlist")
                {
                    hashlist();
                }
                else if(cur == "ciphlist")
                {
                    ciphlist();
                }
                else if(cur == "h" || cur == "help")
                {
                    help();
                }
                else if(cur == "dhtest")
                {
                    dhtest(programParams);
                }
                else if(cur == "-force")
                {
                    programParams.force = true;
                }
                else if(cur == "bundle" || cur == "b" || cur == "claim")
                {
                    string contact = args[++i];
                    string file = args[++i];
                    string ofile = args[++i];

                    Contact c;
                    decodeFile(c, contact);
                    cout << "Password: "; 
                    string password = getPassword();
                    bundleFile(file, ofile, c, password, programParams.h);
                }
                else if (cur == "debundle" || cur == "db")
                {
                    string file = args[++i];
                    string ofile = args[++i];
                    AsymmetricAuthenticationSignature aas = debundleFile(file, ofile);

                    // Export the signer.
                    if(programParams.exportSigners.length())
                    {
                        Contact c(aas.contact());
                        encodeFile(c, programParams.exportSigners);
                    }

                    cout << "Signed by: " << aas.contact().person.identity << endl << "UID: 0x" << aas.contact().uidHex() << endl;
                    cout << "Hash Algorithm: " << getHashName(aas.hashType()) << endl;
                    cout << (aas.verify(ofile) ? "Signature Verified" : "Signature Verification Failed") << endl;
           
                }
                else if(cur == "-prompt")
                {
                    string question = args[++i];
                    cout << question << endl;
                    cout << "Answer: " << endl;

                    string answer;
                    getline(cin, answer);
                    
                    programParams.symmetricAuthentications.push_back(make_tuple(question, answer));
                }
                else if(cur == "-prompt-hidden")
                {
                    string question = args[++i];
                    cout << question << endl;
                    cout << "Answer: " << endl;

                    string answer = getPassword();
                    programParams.symmetricAuthentications.push_back(make_tuple(question, answer));
                }
                else if(cur == "-add-message")
                {
                    cout << "Message: ";
                    getline(cin, command);
                    programParams.messages.push_back(command);
                }
                else if(cur == "-add-message-hidden")
                {
                    cout << "Message: ";
                    command = getPassword();
                    programParams.messages.push_back(command);
                }
                else if (cur == "-drop")
                {
                    programParams.symmetricAuthentications.clear();
                    programParams.messages.clear();
                }
                else if(cur == "contact" || cur == "c")
                {
                    contact(programParams, args[++i]);
                }
                else if(cur == "exc")
                {
                    string in = args[++i];
                    string out = args[++i];
                    extractContact(programParams, in, out);
                }
                // Allows someone to export the signers of a message.
                else if(cur == "-exportSigners" || cur == "-exportSigner" || cur == "-exportAuthors" || cur == "-exportAuthor")
                {
                    programParams.exportSigners = args[++i];
                }
                else if(cur == "to")
                {
                    string con = args[++i];
                    string file = args[++i];
                    string ofile = args[++i];
                    to(programParams, con, file, ofile, true);
                }
                else if(cur == "pe")
                {
                    command = args[++i];
                    previewEncrypted(programParams, command);
                }
                else if(cur == "pc")
                {
                    command = args[++i];
                    previewContact(command);
                }
                else if(cur == "open" || cur == "o")
                {
                    string file = args[++i];
                    string ofile = args[++i];

                    open(programParams, file, ofile);
                }
                else if(cur == "exdhc")
                {
                    string file = args[++i];
                    string ofile = args[++i];
                    DHParameters dh = extractDHParameters_c(file);
                    encodeFile(dh, ofile);
                }
                else if(cur == "exdhe")
                {
                    string file = args[++i];
                    string ofile = args[++i];
                    DHParameters dh = extractDHParameters_e(file);
                    encodeFile(dh, ofile);
                }
                else if(cur == "sign" || cur == "s")
                {
                     string from = args[++i];
                     string file = args[++i];
                     string ofile = args[++i];
                     sign(programParams, from, file, ofile);
                }
                else if(cur == "verify" || cur == "v")
                {
                    string sig = args[++i];
                    string file = args[++i];
                    verify(programParams, sig, file);
                }
                else if(cur == "from")
                {
                    programParams.from = args[++i];
                }
                else if(cur == "ldh")
                {
                    decodeFile(programParams.dh, args[++i]);
                }
                else if(cur == "check")
                {
                    checkContact(programParams, args[++i]);
                }
                else if(cur == "pdh")
                {
                    pdh(programParams.dh);
                }
                else if(cur == "pldh")
                {
                    DHParameters dh;
                    decodeFile(dh, args[++i]);
                    pdh(dh);
                }
            }
        }
    }
    else
    {    
        help();
    }

    return 0;
}
