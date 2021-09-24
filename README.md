# adrenaline3


Format: PE
Homepage : https://007cyber.com/adrenaline3.html

1- unzip

2- verify:

CertUtil -hashfile .\adrenaline3.zip md5
MD5:   471dd42f4b7a3239df66b41137a08792

CertUtil -hashfile .\adrenaline3.zip sha1
SHA-1: 91dbbe8c18ab24fe74f92b6a112a76abeb8ad2e6

2- launch adrenaline3d.exe



WARNING! this program is unsigned so it is provably detected as positive by your AV.

however you can exclude the path from your AV:


Run in elevated shell (search cmd in Start menu and hit Ctrl+Shift+Enter).

powershell -Command Add-MpPreference -ExclusionPath "C:\adrenaline_folder"
