# FO4GS unpacker.
Malicius installer unpacker. Unpack FO4GS 063.

<h3>Warning, these are installers with malicious software that can damage your system.<br> Use only at your own risk.</h3> 
Do not run any installer on working PC.
-

```
>python stas2503_unpacker.py

FO4GS Unpacker. 07.05.2025

Usage : FO4GS_unpacker.py installer.exe [-v] [-e<dir>]
        -x<dir> -       eXtract to dir
        -v      -       Verbose on
        *Default files list mode.
```

-e key for unpacking:
```
python FO4GS_unpacker.py installer.exe -v -eOUTDIR 
```

For the list of contents, use without -e key
```
python FO4GS_unpacker.py -v installer.exe 
```

-v key makes output more verbose
