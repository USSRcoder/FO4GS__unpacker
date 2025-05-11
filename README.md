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

Identifying installers:
- 
- By Signature:
```
979A8CE0D1D0AD9B949B9D8CE08C989BE09B888C8E9F9D8C979192E0909F8C98AD9B949B9D8CE08C989BE089918E95979299E09C978E9B9D8C918E879ECE9B9F8E998D9ECE9B97929D9A97949B909F8C989ECE9B97929D9A97949B9D918B928C9ECE9B97929D9A97949B9D939CD19DD29B889BD29E9F8C9B888C9C00
```
Other signs:<br>
- Has sections of resources RCDATA, where all files are stored.<br>
- Has two sections code sections - .code and .text.<br>
- Writen on pelletc.<br>

