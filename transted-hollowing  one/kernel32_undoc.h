#pragma once

#include <Windows.h>
#include <ntstatus.h>

//don't forget to load functiond before use:
//load_kernel32_functions();
//

BOOL
(WINAPI* CreateProcessInternalW)(HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken
    );


BOOL load_kernel32_functions()
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32");
    CreateProcessInternalW = (BOOL(WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE)) GetProcAddress(hKernel32, "CreateProcessInternalW");
    if (CreateProcessInternalW == NULL) return FALSE;

    return TRUE;
}

extern "C" {
    typedef enum _SECTION_INHERIT
    {
        ViewShare = 1,
        ViewUnmap = 2

    } SECTION_INHERIT;

    typedef struct _UNICODE_STRING
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;

    } UNICODE_STRING, * PUNICODE_STRING;

    typedef struct _OBJECT_ATTRIBUTES
    {
        ULONG Length;
        HANDLE RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG Attributes;
        PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
        PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE

    } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


    NTSYSAPI
        NTSTATUS
        NTAPI
        NtCreateSection(
            OUT PHANDLE SectionHandle,
            IN  ACCESS_MASK DesiredAccess,
            IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
            IN  PLARGE_INTEGER MaximumSize OPTIONAL,
            IN  ULONG SectionPageProtection,
            IN  ULONG AllocationAttributes,
            IN  HANDLE FileHandle OPTIONAL
        );

    NTSYSAPI
        NTSTATUS
        NTAPI
        NtMapViewOfSection(
            IN HANDLE SectionHandle,
            IN HANDLE ProcessHandle,
            IN OUT PVOID* BaseAddress,
            IN ULONG_PTR ZeroBits,
            IN SIZE_T CommitSize,
            IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
            IN OUT PSIZE_T ViewSize,
            IN SECTION_INHERIT InheritDisposition,
            IN ULONG AllocationType,
            IN ULONG Protect
        );


}