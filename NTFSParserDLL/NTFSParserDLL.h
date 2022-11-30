#pragma once

#include "NTFS.h"
#include "NTFS_DataType.h"

extern "C" HANDLE __declspec(dllexport) StealthOpenFile(char* filePathCStr);
extern "C" DWORD __declspec(dllexport) StealthReadFile(FileInfo_t * fileInfo, BYTE * buffer, DWORD bufferSize, ULONGLONG offset, DWORD * bytesRead, ULONGLONG * dataRemaining, ULONGLONG fileSize);
extern "C" void __declspec(dllexport) StealthCloseFile(FileInfo_t * fileInfo);
