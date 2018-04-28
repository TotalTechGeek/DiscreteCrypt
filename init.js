
// cryptopp
Resource("https://www.cryptopp.com/cryptopp700.zip", "cryptopp.zip", function(f)
{
    extract2(f, "cryptopp")
})

// For cryptopp
if(isWindows())
{
    var make = "make"
    if(detect("mingw32-make")) make = "mingw32-make"
    sys("cd cryptopp & " + make)
}
else
{
    sys("cd cryptopp; make")
}


// cppcrypto
Resource("http://cfhcable.dl.sourceforge.net/project/cppcrypto/cppcrypto-0.17-src.zip", "cppcrypto.zip", function(f)
{
    extract2(f, "cppcrypto")
})

function make_program()
{
    var make = "make"
    if(detect("mingw32-make")) make = "mingw32-make"

    sys(make, function()
    {
        if(detect("upx")) sys("upx build/cryptotool.exe --lzma")
        say("Program built.")    
    })
}

if(!detect("g++"))
{
    say ("This built to work with g++ (or compatible) compilers.")
    if(isWindows() && detect("cl"))
    say ("Visual Studio is not supported.")
}

if(isWindows())
{
    say("Building for Windows.")

    var make = "make UNAME=Cygwin"
    
    // if it isn't pure Cygwin though, use this approach instead.
    if(detect("mingw32-make"))
    {
        copy("resources/Makefile", "cppcrypto/cppcrypto/Makefile")
        // copy file mod in here.
        make = "mingw32-make UNAME=Cygwin"
    }

    if(!detect("yasm"))
    {
        // downloads yasm for windows
        Resource("http://www.tortall.net/projects/yasm/releases/yasm-1.3.0-win64.exe", "cppcrypto/cppcrypto/yasm.exe", function() {});
    }

    sys("cd cppcrypto/cppcrypto & " + make);
}
else 
{
    say("Building for Unix.")
    // Linux / Mac
    if(!exists("utils/yasm") && !detect("yasm"))
    {
        // yasm
        Resource("http://www.tortall.net/projects/yasm/releases/yasm-1.3.0.tar.gz", "yasm.tar.gz", function(f)
        {
            extract(f)
            extract("yasm.tar")
            
            sys("mkdir utils; cd yasm-1.3.0; sh configure; make", function()
            {
                copy("yasm-1.3.0/yasm", "utils/yasm")
                sys("PATH=$PATH:" + gwd() + "/utils; cd cppcrypto/cppcrypto; make")
            })
        })
    }
    else
    if(exists("utils"))
    {
        sys("PATH=$PATH:" + gwd() + "/utils; cd cppcrypto/cppcrypto; make")
    }
    else
    {
        sys("cd cppcrypto/cppcrypto; make")
    }
}


if(!exists("build"))
{
    sys("mkdir build");            
}
        

say("Waiting for Resources")
waitAll()
say("Resources done.")

make_program()
