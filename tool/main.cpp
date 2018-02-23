#include <array>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
#include <assert.h>

#include "../cryptopp/osrng.h"
#include "../cryptopp/integer.h"
#include "../cryptopp/nbtheory.h"

#include "Parameters.h"
#include "toolCrypto.h"

using namespace std;

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
        else if(command == "to")
        {
            string file;
            cout << "Contact File: ";
            getline(cin, command);
            command.append(".contact");
            
            Contact recipient, sender;

            decodeFile(recipient, command);

            Integer priv = createContact(sender, recipient.dh, recipient.sp);

            cout << "To Send: ";
            getline(cin, file);

            FileProperties fp;
            fp.ht = h;
            fp.hash = hashFile(file, h);
            fp.cp = cp;
        

            cout << "Out File: ";
            getline(cin, command);

            Integer p = a_exp_b_mod_c(recipient.person.publicKey, priv, recipient.dh.mod());
            Exchange ex(recipient.person, sender.person, recipient.sp, cp, recipient.dh);
            
            encryptFile(file, command, ex, fp, (unsigned char*)intToScrypt(p, ex.sp, getCipherKeySize(fp.cp.cipherType)).c_str());
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
            FileProperties fp;

            decodeEncrypted(ex, fp, command);

            cout << ex.alice.identity << endl << ex.bob.identity << endl;
            cout << (int)fp.cp.cipherType << endl << getCipherName(fp.cp.cipherType) << endl;
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
            FileProperties fp;
            decodeEncrypted(ex, fp, command);
            
            dh = ex.dh;
        }
        // extracts a contact from an encrypted file
        else if(command == "exc")
        {

            cout << "In File: ";
            getline(cin, command);
            Exchange ex;
            FileProperties fp;

            decodeEncrypted(ex, fp, command);
            
            cout << "1) " << ex.alice.identity << endl << "2) " << ex.bob.identity << endl;

            getline(cin, command);

            Contact c;
            c.dh = ex.dh;
            c.sp = ex.sp;
            if(command == "1")
            {
                c.person = ex.alice;    
            }
            else
            {
                c.person = ex.bob;
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
            string salt, file;
            cout << "In File: ";
            getline(cin, file);
            
            Exchange ex;
            FileProperties fp;
            decodeEncrypted(ex, fp, file);

            
            cout << "1) " << ex.alice.identity << endl << "2) " << ex.bob.identity << endl;
            getline(cin, command);

            Integer pub;
            if(command == "1")
            {
                salt = ex.alice.salt;
                pub = ex.bob.publicKey;
            }
            else
            {
                salt = ex.bob.salt;
                pub = ex.alice.publicKey;
            }

            cout << "Password: ";
            command = getPassword();

            Integer priv;
            priv.Decode((unsigned char*)getScrypt(command, salt, ex.sp.N, ex.sp.P, ex.sp.R, ex.sp.len).c_str(), ex.sp.len);
            Integer p = a_exp_b_mod_c(pub, priv, ex.dh.mod());

            cout << "Out File: ";
            getline(cin, command);
            decryptFile(file, command, ex, fp, (unsigned char*)intToScrypt(p, ex.sp, getCipherKeySize(fp.cp.cipherType)).c_str());
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
