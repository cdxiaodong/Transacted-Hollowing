#pragma once

#include <Windows.h>
#include <ntstatus.h>
#include <iostream>

bool redirect_to_payload(BYTE* loaded_pe, PVOID load_base, PROCESS_INFORMATION& pi, bool is32bit);

wchar_t* get_file_name(wchar_t* full_path);


WORD get_pe_architecture(const BYTE* pe_buffer);

DWORD get_entry_point_rva(const BYTE* pe_buffer);


