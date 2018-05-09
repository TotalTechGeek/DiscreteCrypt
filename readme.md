# DiscreteCrypt

![Imgur](https://svgshare.com/i/67o.svg)

This tool is an alternative to software like PGP, with a focus on Discrete Log Cryptography. The algorithm is currently in v2.2.5.

The tool features powerful authenticated encryption, dozens of strong symmetric ciphers and hash algorithms, future-proof design choices, and a variety of other features (like OTR-Style symmetric authentication, anonymous senders, etc). 

## Usability

The tool is pretty user-friendly to people with command-line experience. Encrypting a file securely (with default parameters) is as simple as:  

```bash
cryptotool -to alice file file.enc # Encrypts a file anonymously to alice
```

Creating a "contact" for yourself is as simple as:

```bash
cryptotool -contact bob # Creates a contact in a file called "bob"
```

And opening a file is as simple as:
```bash
cryptotool -open file.enc file # Opens the encrypted file
```

## To Build

This algorithm uses a build tool I wrote called "dave". It requires Java 8+ or greater. 

To build run 
``` 
java -jar Dave.jar
```

Which will execute the init script. This will build the code for x86, x86_64, and ARM platforms. It might build for other platforms, but caveat emptor. Due to the use of digestpp, it is unlikely the full project will build for non-little endian platforms.  

The tool will grab the necessary dependencies to build the project (like cryptopp, digestpp, and my modified kuznyechik library).

This tool is developed to compile with g++, clang (aliased as g++), and Mingw32_64. The compiler must have C++11 support.

If building on Windows, it is recommended that you build the project from either [cmder](http://cmder.net/) or a unix-like shell. 

MSVC support may be added in the future.

## Features

DiscreteCrypt is a powerful replacement for tools that are similar to PGP. It supports a plethora of features, like deniable encryption, symmetric authentication, signature bundling, multiple recipients, and much more. 

With a focus on customizability, the tool supports a total of 43 unique cipher options, featuring algorithms like AES, Kuznyechik, Camellia, and Threefish. The tool similarly supports 39 unique hashing options, including the SHA2 family, SHA3, Whirlpool, and Skein.

Internally, the tool uses Scrypt for key derivation, which is tuned to mitigate brute-force attacks.  

A full list is available in the user documentation. 

## User Documentation

The documentation for the tool is available [here](http://totaltechgeek.github.io/DiscreteCrypt/DiscreteCrypt%20Documentation.html).

## Download

Check the releases tab [here](https://github.com/TotalTechGeek/DiscreteCrypt/releases). 
