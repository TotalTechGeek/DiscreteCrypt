# DiscreteCrypt
---

Documentation for this tool is on the way. It's going to be an alternative to something like PGP, using Discrete Log Cryptography. The algorithm is currently in v1 and the interface is quite clunky.

At the moment the focus is on developing the functionality. 


## To Build

This algorithm uses a build tool I wrote called "dave"

To build run 
``` 
java -jar Dave.jar
```

Which will execute the init script. This will build the code for x86/x86_64 platforms.

The tool will grab the necessary dependencies to build the project (like cryptopp, cppcrypto, and potentially yasm).

This tool is developed to compile with gcc, and Mingw32_64. MSVC support may be added in the future.