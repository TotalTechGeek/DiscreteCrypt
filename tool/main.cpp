#include <array>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
#include <sstream>
#include <assert.h>

#include "../cryptopp/osrng.h"
#include "../cryptopp/integer.h"
#include "../cryptopp/nbtheory.h"

#include "Parameters.h"
#include "toolCrypto.h"

using namespace std;


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


// Ignore this rambling. These are just notes to myself. //
// I'll keep things somewhat ephemeral. Each person can specify a preferred method of contact, or use the current session to reply, 
// or use ephemeral, it really doesn't matter.

// I think a decent program will allow you to claim different "salt" identifiers, and will let you keep track of sub-passwords with one master password.
// You will not be forced to do this. You can just default to using the same password.

// I will still want to add hashing as the nonce for the salt step in the Scrypt Function.

// Replying will use the current exchange, but will of course switch out the nonce based on the file, 
// * (Except when a person's preferred params are supplied), that will be config based.
// Extraction then sending will use ephemeral.

// The identity field will eventually use JSON.
// So you might be able to specify tags saying "Oh yeah, feel free to contact me using this session."

int main()
{
    using CryptoPP::Integer;
    using CryptoPP::OS_GenerateRandomBlock;
    ScryptParameters sp;
    CipherParams cp;
    HashType h = HashType::SHA256;
    DHParameters dh("2", "47769438302540021096046443384978134814892753148995001100435849309801466711663622675763277561771586643466880132533087023976743720746114313685955475444589604417407040697888976978390583956623556758141737474347378435226827837774896742010138917035181496312250563068059450412947491330151828692648018138087943927636572818119324452596730516782404332695754162772658498436841083547989339855356853145414644716280526952238204193911949774915160700045679030240088906618979624377203573807795121870524572040515228739829252884815670239587909743396659766160612006380563578633815689354481428440538907836892141942976841851997058146892101157");
    string command;

    cout << "> ";
    getline(cin, command);

    while(command != "quit" && command != "exit")
    {
        // This is temporary.
        if(command == "help" || command == "h")
        {
            cout << "Note that this program is really clunky and more of a proof of concept" << endl;
            cout << "Enter commands alone. No spaces. This is not a sophisticated program" << endl;

            cout << "c" << "\t\t" << "Creates a contact." << endl;
            cout << "to" << "\t\t" << "Encrypts file for a contact." << endl;
            cout << "open" << "\t\t" << "Opens a file" << endl;
            cout << "check" << "\t\t" << "Checks if your password matches a contact file." << endl;

            cout << "ciph" << "\t\t" << "Sets a cipher used." << endl;
            cout << "ciphlist" << "\t" << "Prints out all the ciphers available." << endl;
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
        else if(command == "c" || command == "contact")
        {
            Contact con;
            createContact(con, dh, sp);
            cout << "Out File: ";
            getline(cin, command);
            command.append(".contact");
            encodeFile(con, command);
        }
        // sets the cipher mode
        else if(command == "ciph")
        {
            cout << "Cipher Mode: ";
            getline(cin, command);
            cp.cipherType = (CipherType)stoi(command, 0, 8);
            cout << getCipherName(cp.cipherType) << endl; 
        }
        else if(command == "hash")
        {
            cout << "Hash Mode: ";
            getline(cin, command);
            h = (HashType)stoi(command, 0, 8);
            cout << getHashName(h) << endl;
        }
        else if(command == "hashList")
        {
            for(int i = 0; i < sizeof(AVAILABLE_HASHES_CODES) / sizeof(uint16_t); i++)
            {
                cout << AVAILABLE_HASHES[i] << " - " << std::oct << AVAILABLE_HASHES_CODES[i] << endl;
                cout << std::dec;
            }   
        }
        else if(command == "to")
        {
            string file;
            cout << "Contact File: ";
            getline(cin, command);
            
            vector<Contact> recipients;
            vector<DataExtension> extensions;
            vector<string> recipients_s;

            StringSplitFunctions::splitString(recipients_s, command, ",");

            for(int i = 0; i < recipients_s.size(); i++)
            {
                Contact recipient;
                recipients_s[i].append(".contact");
                decodeFile(recipient, recipients_s[i]);
                recipients.push_back(recipient);
            }

            cout << "To Send: ";
            getline(cin, file);

            FileProperties fp(cp, h);
           
            hmacFile(file, fp);

            cout << "Out File: ";
            getline(cin, command);

            string password("");
    
            fp.recipients = recipients.size();
            fp.extensions = extensions.size();
            
            encryptFile(file, command, recipients, extensions, fp, password);
        }
        // allows you to specify the DH Params for creating contacts.
        else if(command == "dh")
        {         
            cout << "Generator: ";
            getline(cin, command);

            dh.gen(Integer(command.c_str()));

            cout << "Modulus: ";
            getline(cin, command);

            dh.mod(Integer(command.c_str()));
        }
        else if(command == "sdh")
        {
            cout << "Out File: ";
            getline(cin, command);
            command.append(".dh");
            encodeFile(dh, command);
        }
        else if(command == "pdh")
        {
            cout << dh.gen() << endl << endl;
            cout << dh.mod() << " (" << dh.mod().BitCount() << ")" << endl;
        }
        else if(command == "pdh2")
        {
            Integer m = dh.mod() - 1;
            for(int i = 2; i < 65536; i++)
            {
                while(!(m % i) && (m != i)) m /= i;
            }

            cout << dh.gen() << endl << endl;
            cout << m << " (" << m.BitCount() << ")" << endl;
        }
        else if(command == "dhtest")
        {
            CryptoPP::AutoSeededRandomPool rnd;
            cout << dh.mod() << " (" << dh.mod().BitCount() << ")" << endl;
            bool mod = IsPrime(dh.mod()) && RabinMillerTest(rnd, dh.mod(), 3); 
            cout << (mod ? "Valid" : "Invalid") << endl;


            Integer m = dh.mod() - 1;
            for(int i = 2; i < 65536; i++)
            {
                while(!(m % i) && (m != i)) m /= i;
            }

            cout << dh.gen() << endl << endl;
            cout << m << " (" << m.BitCount() << ")" << endl;

            bool poh = IsPrime(m) && RabinMillerTest(rnd, m, 3);
            cout << (poh ? "Valid" : "Invalid") << endl;

            cout << endl;
            cout << ((poh&&mod) ? "Verified" : "Bad Parameters") << endl;


        }
        else if(command == "ciphlist")
        {   
            for(int i = 0; i < sizeof(AVAILABLE_CIPHERS_CODES) / sizeof(int16_t); i++)
            {
                cout << AVAILABLE_CIPHERS[i] << " - " << std::oct << AVAILABLE_CIPHERS_CODES[i] << endl;
            }
            cout << std::dec;

        }
        else if(command == "ldh")
        {
            cout << "In File: ";
            getline(cin, command);
            command.append(".dh");
            
            decodeFile(dh, command);
        }
        // gets dh params from a contact
        else if(command == "cldh")
        {
            cout << "Contact File: ";
            getline(cin, command);
            command.append(".contact");

            Contact c;
            decodeFile(c, command);

            dh = c.dh;
        }
        else if(command == "pe")
        {
            cout << "In File: ";
            getline(cin, command);
            Exchange ex;
            FileProperties fp(cp, h);
            vector<Exchange> exchanges;
            vector<DataExtension> extensions;
            decodeEncrypted(exchanges, extensions, fp, command);

            cout << "File Format Version: " << (int)fp.version << endl << endl;
            cout << "People: " << endl;
            for(int i = 0; i < exchanges.size(); i++)
            {
                cout << exchanges[i].alice.identity << " (0x" << exchanges[i].alice.saltHex() << ")" << endl
                << exchanges[i].bob.identity << " (0x" << exchanges[i].bob.saltHex() << ")" << endl;
            }
            cout << endl;

            cout << "Cipher: " << getCipherName(fp.cp.cipherType) << endl << "Hash: " << getHashName(fp.ht) << endl << endl;
            

            cout << "Extension count: " << fp.extensions << endl;
            
        }
        // prints out the contact info.
        else if(command == "pc")
        {
            cout << "Contact File: ";
            getline(cin, command);
            command.append(".contact");
            
            Contact con;
            decodeFile(con, command);

            cout << "Identity: " << con.person.identity << endl
                 << "Salt: 0x" << con.person.saltHex() << endl
                 << "Public Key: " << con.person.publicKey << endl;

            cout << endl;
            cout << "Generator: " << con.dh.gen() << endl
                 << "Modulus: " << con.dh.mod() << " (" << con.dh.mod().BitCount() << ")" << endl;
            
        }
        // loads dh parameters from an encrypted file.
        else if(command == "eldh")
        {
            cout << "In File: ";
            getline(cin, command);
            
            Exchange ex;
            FileProperties fp(cp, h);
            vector<Exchange> exchanges;
            vector<DataExtension> extensions;
            decodeEncrypted(exchanges, extensions, fp, command);
            
            for(int i = 0; i < exchanges.size(); i++)
            {
                cout << (i+1) << ") " << exchanges[i].dh.mod() << " (" << exchanges[i].dh.mod().BitCount() << ")" << endl; 
            }

            getline(cin, command);

            dh = exchanges[stoi(command) - 1].dh;
        }
        // extracts a contact from an encrypted file
        else if(command == "exc")
        {

            cout << "In File: ";
            getline(cin, command);
            vector<Exchange> exchanges;
            vector<DataExtension> extensions;
            FileProperties fp(cp, h);

            decodeEncrypted(exchanges, extensions, fp, command);
            Exchange ex;
            
             for(int i = 0; i < exchanges.size(); i++)
            {
                ex = exchanges[i];
                cout << (i*2+1) << ") " << ex.alice.identity << endl << (i*2+2) << ") " << ex.bob.identity << endl;
            }

            getline(cin, command);
            int person = stoi(command) - 1;
            ex = exchanges[person/2];
            Contact c;

            c.dh = ex.dh;
            c.sp = ex.sp;

            if(person & 1)
            {
                c.person = ex.bob;    
            }
            else
            {
                c.person = ex.alice;
            }

            cout << "Out File: ";
            getline(cin, command);
            command.append(".contact");

            encodeFile(c, command);
        }
        else if(command == "check")
        {
            cout << "Contact File: ";
            getline(cin, command);
            command.append(".contact");
            
            Contact con;
            decodeFile(con, command);

            cout << "Password: "; 
            string password = getPassword();

            // Compute the private and public values.
            Integer priv;
            priv.Decode((unsigned char*)getScrypt(password, con.person.salt, con.sp.N, con.sp.P, con.sp.R, con.sp.len).c_str(), con.sp.len);
            Integer pub = a_exp_b_mod_c(con.dh.gen(), priv, con.dh.mod());

            if(pub == con.person.publicKey)
            {
                cout << "Verified" << endl;
            }
            else
            {
                cout << "Not Verified" << endl;
            }
        }
        else if(command == "open" || command == "o")
        {
            string file, password;
            int person;
            cout << "In File: ";
            getline(cin, file);
            
            Exchange ex;
            FileProperties fp(cp, h);

            vector<Exchange> exchanges;
            vector<DataExtension> extensions;
            decodeEncrypted(exchanges, extensions, fp, file);

            for(int i = 0; i < exchanges.size(); i++)
            {
                ex = exchanges[i];
                cout << (i*2+1) << ") " << ex.alice.identity << endl << (i*2+2) << ") " << ex.bob.identity << endl;
            }
            getline(cin, command);

            person = stoi(command) - 1;

            cout << "Password: ";
            password = getPassword();

            cout << "Out File: ";
            getline(cin, command);

            cout << (decryptFile(file, command, exchanges, fp, password, person) ? "Success" : "Fail") << endl;
        }
        else
        {
            // This is also a cheap hack and will be removed.
            system(command.c_str());
        }

        cout << "> ";
        getline(cin, command);
    }

    return 0;
}
