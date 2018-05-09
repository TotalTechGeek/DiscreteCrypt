
// cryptopp
Resource("https://www.cryptopp.com/cryptopp700.zip", "cryptopp.zip", function(f)
{
    extract2(f, "cryptopp")
})


function build(x)
{
    // For cryptopp
    if(isWindows())
    {
        var make = "make"
        if(detect("mingw32-make")) make = "mingw32-make"
        sys("cd " + x + " & " + make)
    }
    else
    {
        sys("cd " + x + "; make")
    }
}

if(!detect("git"))
{
    say("Warning: The current build script requires git.")
}

build('cryptopp')

if(exists("kuznechik"))
{
    build('kuznechik')    
}
else
{
    sys("git clone https://github.com/TotalTechGeek/kuznechik", function()
    {    
        if(exists("ARM")) copy("resources/kuz", "kuznechik/Makefile")
        build('kuznechik')    
    })
}

if(!exists("digestpp"))
sys("git clone https://github.com/kerukuro/digestpp", function()
{

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

if(!exists("build"))
{
    sys("mkdir build");            
}
        

say("Waiting for Resources")
waitAll()
say("Resources done.")

make_program()
