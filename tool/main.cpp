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
    
    bool sym = false;
    HashType h = HashType::SHA256;
    DHParameters dh = DHParameters("2", "1236027852723267358067496240415081192016632901798652377386974104662393263762300791015297301419782476103015366958792837873764932552461292791165884073898812814414137342163134112441573878695866548152604326906481241134560091096795607547486746060322717834549300353793656273878542405925895784382400028374603183267116520399667622873636417533621785188753096887486165751218947390793886174932206305484313257628695734926449809428884085464402485504798782585345665225579018127843073619788513405272670558284073983759985451287742892999484270521626583252756445695489268987027078838378407733148367649564107237496006094048593708959670063677802988307113944522310326616125731276572628521088574537964296697257866765026848588469121515995674723869067535040253689232576404893685613618463095967906841853447414047313021676108205138971649482561844148237707440562831931089544088821151806962538015278155763187487878945694840272084274212918033049841007502061");
    
    string from;

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
    cout << (aas.verify(file) ? "Verified" : "Not Verified") << endl;
}

void to(ProgramParams& programParams, const string& contact, const string& file, const string& ofile, bool cli = false)
{
    string password("");
    vector<Contact> recipients;
    vector<DataExtension> extensions;
    vector<string> recipients_s;
    StringSplitFunctions::splitString(recipients_s, contact, ",");
    for(int i = 0; i < recipients_s.size(); i++)
    {
        Contact recipient;
        if(!cli) recipients_s[i].append(".contact");
        decodeFile(recipient, recipients_s[i]);
        recipients.push_back(recipient);
    }
        
    Contact fromCon;
    Contact* con = 0;
        
    // bad debug command to test sending "from"
    if(programParams.from.length())
    {
        cout << "Password for " << programParams.from << ": ";
        password = getPassword();
        decodeFile(fromCon, programParams.from);
        if(fromCon.verify(password))
        {
            AsymmetricAuthenticationExtension aae(fromCon, file, password, programParams.h);
            con = &fromCon;
            extensions.push_back(aae.outData());
        }
        else
        {
            password = "";
        }                
    }
    // This is a bad debug command.
    if(programParams.sym)
    {
        string question, answer;
        cout << "Symmetric Challenge: ";
        getline(cin, question);
        while(question != "-1")
        {                    
            getline(cin, answer);
            SymmetricAuthenticationExtension sae(question, answer, file, programParams.h);
            extensions.push_back(sae.out());
            cout << "Symmetric Challenge: ";
            getline(cin, question);
        }
    }
    FileProperties fp(programParams.cp, programParams.h);
    hmacFile(file, extensions, fp);
        
    fp.recipients = recipients.size();
    fp.extensions = extensions.size();
    encryptFile(file, ofile, recipients, extensions, fp, password, con);
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
    cout << "Note that this program is really clunky and more of a proof of concept" << endl;
    cout << "Enter commands alone. No spaces. This is not a sophisticated program" << endl;
    cout << "c" << "\t\t" << "Creates a contact." << endl;
    cout << "to" << "\t\t" << "Encrypts file for a contact." << endl;
    cout << "open" << "\t\t" << "Opens a file" << endl;
    cout << "check" << "\t\t" << "Checks if your password matches a contact file." << endl;
    cout << "ciph" << "\t\t" << "Sets a cipher used." << endl;
    cout << "ciphlist" << "\t" << "Prints out all the ciphers available." << endl;
    cout << "hash" << "\t\t" << "Sets the hash used." << endl;
    cout << "hashlist" << "\t" << "Prints out all the hash functions available." << endl;
    cout << "sign" << "\t\t" << "Asymmetrically signs a file using a contact." << endl;
    cout << "verify" << "\t\t" << "Verifies a file from its signature file." << endl;
    cout << "dh" << "\t\t" << "Lets you set Discrete Log Parameters." << endl;
    cout << "ldh" << "\t\t" << "Loads discrete log parameters from a file." << endl;
    cout << "sdh" << "\t\t" << "Saves discrete log parameters to a file." << endl;
    cout << "eldh" << "\t\t" << "Loads discrete log parameters from an encrypted file." << endl;
    cout << "cldh" << "\t\t" << "Loads discrete log parameters from a contact file." << endl;
    cout << "pdh" << "\t\t" << "Prints discrete log parameters." << endl;
    cout << "exc" << "\t\t" << "Extracts a contact from a file." << endl;
    cout << "pc" << "\t\t" << "Prints contact information." << endl;
    cout << "pe" << "\t\t" << "Prints encrypted file information." << endl;
    cout << "exit" << "\t\t" << "Exits the program." << endl;
}


void help2()
{
    cout << "-contact <output file>" << "\t\t\t\t" << "Creates a contact." << endl;
    cout << "-to <contact files> <input file> <output file>" << "\t" << "Encrypts file for a contact." << endl;
    cout << "-open <file> <output file>" << "\t\t\t" << "Opens a file" << endl;
    cout << "-check <contact file>" << "\t\t\t\t" << "Checks if password matches a contact file." << endl;
    cout << "-ciphlist" << "\t\t\t\t\t" << "Prints out all the ciphers available." << endl;
    cout << "-hash <hash #>" << "\t\t\t\t\t" << "Sets the hash used." << endl;
    cout << "-hashlist" << "\t\t\t\t\t" << "Prints out all the hash functions available." << endl;
    // cout << "dh" << " " << "Lets you set Discrete Log Parameters." << endl;
    cout << "-ldh <dh file>" << "\t\t\t\t\t" << "Loads discrete log parameters from a file." << endl;
    cout << "-from <contact file>" << "\t\t\t\t" << "Sets which contact files are from." << endl;
    cout << "-sign <contact file> <in file> <out file>" << "\t" << "Signs a file using a contact." << endl;
    cout << "-verify <sig file> <out file>" << "\t\t\t" << "Verifies a file from its signature." << endl;
    
    // cout << "sdh" << " " << "Saves discrete log parameters to a file." << endl;
    // cout << "eldh" << " " << "Loads discrete log parameters from an encrypted file." << endl;
    // cout << "cldh" << " " << "Loads discrete log parameters from a contact file." << endl;
    // cout << "pdh" << " " << "Prints discrete log parameters." << endl;
    // cout << "exc" << " " << "Extracts a contact from a file." << endl;
    cout << "-pc <contact file>" << "\t\t\t\t" << "Prints contact information." << endl;
    cout << "-pe <encrypted file>" << "\t\t\t\t" << "Prints encrypted file information." << endl;
    
}


void open(ProgramParams& programParams, const string& file, const string& ofile)
{
    string password, command;
    int person;
    
    FileProperties fp(programParams.cp, programParams.h);
    vector<Exchange> exchanges;
    vector<DataExtension> extensions;
    decodeEncrypted(exchanges, fp, file);
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
        cout << "=== Symmetric Authentication ===" << endl;
        for(int i = 0; i < extensions.size(); i++)
        {
            if(extensions[i].et == ExtensionType::SYMMETRIC)
            {
                SymmetricAuthenticationExtension sae(extensions[i]);
                cout << sae.prompt() << endl;
                getline(cin, command);
                cout << (sae.check(command, ofile, fp.ht) ? "Success" : "Fail") << endl;                 
            }
        }
        cout << "=== End Symmetric Authentication ===" << endl;
        cout << "=== Asymmetric Authentication ===" << endl;
        for(int i = 0; i < extensions.size(); i++)
        {
            if(extensions[i].et == ExtensionType::ASYMMETRIC)
            {
                AsymmetricAuthenticationExtension aae(extensions[i]);
                cout << (aae.contact().person.identity) << " (0x" << aae.contact().uidHex() << ")" << endl;
                cout << (aae.verify(ofile, fp.ht) ? "Success" : "Fail") << endl;                 
            }
        }
        cout << "=== End Asymmetric Authentication ===" << endl;
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
                    help2();
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
                else if(cur == "sign")
                {
                     string from = args[++i];
                     string file = args[++i];
                     string ofile = args[++i];
                     sign(programParams, from, file, ofile);
                }
                else if(cur == "verify")
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
        cout << "> ";
        getline(cin, command);
        while(command != "quit" && command != "exit")
        {
            // This is temporary.
            if(command == "help" || command == "h")
            {
                help();
            }
            // Bad Debug Commands for extensions lol.
            else if(command == "sym")
            {
                programParams.sym = !programParams.sym;
            }
            else if(command == "from")
            {
                getline(cin, programParams.from);
                programParams.from.append(".contact");
            }
            else if(command == "c" || command == "contact")
            {
                cout << "Out File: ";
                getline(cin, command);
                command.append(".contact");

                contact(programParams, command);
            }
            // sets the cipher mode
            else if(command == "ciph")
            {
                cout << "Cipher Mode: ";
                getline(cin, command);
                ciph(programParams, command);
            }
            else if(command == "hash")
            {
                cout << "Hash Mode: ";
                getline(cin, command);
                hashCommand(programParams, command);
            }
            else if(command == "hashlist")
            {
               hashlist();
            }
            else if(command == "verify")
            {
                string sig, file;

                cout << "Signature File: ";
                getline(cin, sig);
                
                cout << "File: ";
                getline(cin, file);
                
                verify(programParams, sig, file);
            }
            else if(command == "sign")
            {
                string from, file, ofile;

                cout << "Contact File: ";
                getline(cin, from);
                from.append(".contact");

                cout << "File: ";
                getline(cin, file);
                
                cout << "Out File: ";
                getline(cin, ofile);
                    
                sign(programParams, from, file, ofile);
            }
            else if(command == "to")
            {
                string contact, file, ofile;
                cout << "Contact File: ";
                getline(cin, contact);

                cout << "To Send: ";
                getline(cin, file);

                cout << "Out File: ";
                getline(cin, ofile);

                to(programParams, contact, file, ofile);
            }
            // allows you to specify the DH Params for creating contacts.
            else if(command == "dh")
            {         
                cout << "Generator: ";
                getline(cin, command);

                programParams.dh.gen(Integer(command.c_str()));

                cout << "Modulus: ";
                getline(cin, command);

                programParams.dh.mod(Integer(command.c_str()));
            }
            else if(command == "sdh")
            {
                cout << "Out File: ";
                getline(cin, command);
                command.append(".dh");
                encodeFile(programParams.dh, command);
            }
            else if(command == "pdh")
            {
                pdh(programParams.dh);
            }
            else if(command == "dhtest")
            {
            dhtest(programParams);
            }
            else if(command == "ciphlist")
            {   
                ciphlist();
            }
            else if(command == "ldh")
            {
                cout << "In File: ";
                getline(cin, command);
                command.append(".dh");
                
                decodeFile(programParams.dh, command);
            }
            // gets dh params from a contact
            else if(command == "cldh")
            {
                cout << "Contact File: ";
                getline(cin, command);
                command.append(".contact");

                Contact c;
                decodeFile(c, command);

                programParams.dh = c.dh;
            }
            else if(command == "pe")
            {
                cout << "In File: ";
                getline(cin, command);

                previewEncrypted(programParams, command);
            }
            // prints out the contact info.
            else if(command == "pc")
            {
                cout << "Contact File: ";
                getline(cin, command);
                command.append(".contact");
                
                previewContact(command);
            }
            // loads dh parameters from an encrypted file.
            else if(command == "eldh")
            {
                cout << "In File: ";
                getline(cin, command);
               
                programParams.dh = extractDHParameters_e(command);
            }
            // extracts a contact from an encrypted file
            else if(command == "exc")
            {
                string in, out;
                cout << "In File: ";
                getline(cin, in);
                

                cout << "Out File: ";
                getline(cin, out);
                out.append(".contact");

                extractContact(programParams, in, out);
            }
            else if(command == "check")
            {
                cout << "Contact File: ";
                getline(cin, command);
                command.append(".contact");
                checkContact(programParams, command);
            }
            else if(command == "open" || command == "o")
            {
                string file, ofile;

                cout << "In File: ";
                getline(cin, file);

                cout << "Out File: ";
                getline(cin, ofile);
                
                open(programParams, file, ofile);
            }
            else
            {
                // This is also a cheap hack and will be removed.
                system(command.c_str());
            }

            cout << "> ";
            getline(cin, command);
        }
    }

    return 0;
}
