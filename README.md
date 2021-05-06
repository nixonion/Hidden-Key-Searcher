# Hidden-Key-Searcher

A defense mechanism to find and delete registry keys made using the NULL termination method mentioned in the paper given below:
https://github.com/ewhitehats/InvisiblePersistence/blob/master/InvisibleRegValues_Whitepaper.pdf

This tool is written in C++ and uses NTDLL functions to find AUTORUN registry keys that cannot be seen using Registry Editor.


-------------------------
HOW TO USE:

To run the exe (Make sure you are running  it as an administrator):

      example.exe

Once the executable runs, it searches and shows the hidden keys in following registry paths:
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

The output would look something like this:
  
        Searching for NULL Hidden Keys

        -----------------


        Entry Number : 0

        Registry Path   = HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        Name    = NullNullSOFTWARE
        Index   = 0
        Type    = 1
        Datalength      = 66
        Namelength      = 20
        Source  = "C:\WINDOWS\system32\notepad.exe"

        -----------------


        Entry Number : 1

        Registry Path   = HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        Name    = NullNullEVILTEST
        Index   = 0
        Type    = 1
        Datalength      = 8
        Namelength      = 20
        Source  = TEST

After finding the keys, you will be asked whether you want to delete a key. You can provide the entry number of the key to delete it.



