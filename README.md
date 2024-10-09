# triage-collector

triage-collector is a triage collection tool for fast forensic. 
It collects various artifacts on Windows. You can extend additional artifacts 
without compilation as well as pre-defined artifacts.

* RAM
  * with WinPmem
  * with Magnet DumpIt for Windows (needed to place the binary and uncomment the line and comment out the WinPmem lines in triage-collector.ini)
* NTFS
  * $MFT
  * $Logfile
  * $SECURE:$SDS
  * $UsnJrnl:$J
* swap files
  * pagefile.sys
  * swapfile.sys
* Prefetch
* Event log
* Registry
  * Amcache.hve
  * SAM, SECURITY, SOFTWARE, SYSTEM, DEFAULT
  * NTUser.dat, UsrClass.dat
    * for users and service profiles
  * TxR transaction logs
* WMI
* SRUM
* Web
  * History (Chrome)
  * cookies.sqlite, places.sqlite (Firefox)
  * WebCacheV01.dat (IE and Edge)
  * History (Edge)
* Windows.old (if this folder exists)
* User-defined data (under each user and the root directory)
  * Pre-defined rules
    * startup
    * tasks
    * Intune
    * SUM
    * Windows Timeline
    * ntds.dit
    * sysvol
    * RDP cache
    * PowerShell Console History
    * $Recycle.bin
    * Thumb cache and Icon cache
    * Search Indexor
    * Thunderbird (needed to uncomment the line)
    * Outlook (needed to uncomment the line)
    * PCA (Program Compatibility Assistant)
    * BITS database

triage-collector was based on cdir-collector. Since the author ignored my PR, I decided to fork it and modified it a lot.
The differences between this and the original cdir-collector v1.3.6 are:
* To support arbitrally file acquisition
  * Pre-defined artifacts are listed above.
* To support additional artifacts
  * swap files
  * NTFS $Logfile
  * TxR registry transaction
* To support recursive acquisition
* To support 64bit on the triage-collector and ntfsparsedll binaries
* To support acquireing multi-byte files
* To load appropriate winpmem binary automatically according to the platform of the running OS
* New ini parser named inipp
* New ini format
* Refactored many functions
* Changed the import method of the functions on ntfsparsedll

Since I modified and newly created many functions, please test it before using it.

## Download

Binary is available on the following link.

https://github.com/herosi/triage-collector/releases

## Build

If you want to customise and build binary from source code, try to use Visual Studio 2019. 

Component of triage-collector: 
* triage-collector.ini
* triage-collector.exe
* NTFSParserDLL.dll
* libcrypto-41.dll
* libssl-43.dll
* winpmem_mini_x64_rc2.exe
* winpmem_mini_x86.exe
* winpmem.exe (old stuff, optional)
* winpmem-2.1.post4.exe (old stuff, optional)

## How to use

All of component files place into USB stick or file server, then double-click triage-collector.exe. triage-collector requires administrative privilege.
It creates "COMPUTERNAME_YYYYMMDDhhmmss" folder then collected data are stored on this folder. 

If you edit triage-collector.ini, you can switch the acquisition of each data type. You can also add user-defined rules in "[Users]" and "[System]" section.

## Third Party

triage-collector depends on the following library/tools.

* Library: NTFSParserDLL, LibreSSL and inipp,
* Tool: winpmem
  - winpmem.exe is a part of c-aff4 project (https://github.com/Velocidex/c-aff4).  
  - winpmem_mini_x64_rc2.exe and winpmem_mini_x86.exe are from https://github.com/Velocidex/WinPmem  
  - winpmem-2.1.post4.exe is a part of rekall project (https://github.com/google/rekall).  

* Tool: Magnet DumpIt for Windows (optional)
You can download Magnet DumpIt for Windows from https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/  

* Icon logo
Created my logo at LogoMakr.com/app
