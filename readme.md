# DiscreteCrypt
---
![Imgur](https://i.imgur.com/9j1u5T6.png)

This tool is an alternative to software like PGP, with a focus on Discrete Log Cryptography. The algorithm is currently in v2.1, in its first release.

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
