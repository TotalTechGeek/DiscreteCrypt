# DiscreteCrypt

![Imgur](https://svgshare.com/i/67o.svg)

This tool is an alternative to software like PGP, with a focus on Discrete Log Cryptography. The algorithm is currently in v2.2.5.

The tool features powerful authenticated encryption, dozens of strong symmetric ciphers and hash algorithms, future-proof design choices, and a variety of other features (like OTR-Style symmetric authentication, anonymous senders, etc). 

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


## User Documentation

The documentation for the tool is available [here](http://totaltechgeek.github.io/DiscreteCrypt/DiscreteCrypt%20Documentation.html).

## Download

Check the releases tab [here](https://github.com/TotalTechGeek/DiscreteCrypt/releases). 
