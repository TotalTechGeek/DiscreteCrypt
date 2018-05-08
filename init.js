
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

if(!exists("build"))
{
    sys("mkdir build");            
}
        

say("Waiting for Resources")
waitAll()
say("Resources done.")

make_program()
