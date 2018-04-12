#pragma once

#include <Windows.h>
#include "pe_status.h"

BOOL in_arr(_In_ WORD item, _In_ WORD arr[]);
PE_STATUS get_directory_name(_Out_ TCHAR directory_name[], _In_ TCHAR original_name[]);
PE_STATUS validate_path(char str[]);
PE_STATUS get_file_name(_Out_ TCHAR file_name[], _In_ TCHAR original_name[]);
