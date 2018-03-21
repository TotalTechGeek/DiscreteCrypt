# DiscreteCrypt
---

Documentation for this tool is on the way. It's going to be an alternative to something like PGP, using Discrete Log Cryptography. The algorithm is currently in v1.75 and the user experience is a bit clunky.

At the moment the focus is on fully developing the functionality rather than user experience. 

## To Build

This algorithm uses a build tool I wrote called "dave". It requires Java 8+ or greater. 

To build run 
``` 
java -jar Dave.jar
```

Which will execute the init script. This will build the code for x86/x86_64 platforms. ARM support is coming soon. 

The tool will grab the necessary dependencies to build the project (like cryptopp, cppcrypto, and potentially yasm).

This tool is developed to compile with g++, clang (aliased as g++), and Mingw32_64. The compiler must have C++11 support, previous compilers are untested.

MSVC support may be added in the future.

--- 

## Most Useful Commands

#### help

Will give you a list of most of the available commands.

#### c 

Will let you create a (c)ontact file so others will be able to send secure files to you.

#### to 

Will let you send a file to different contacts (comma delimited).

#### open

Will let you open an encrypted file.

---

You are also able to use commands to switch out the Discrete Log parameters, and the different ciphers and hash functions.
