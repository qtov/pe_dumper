#pragma once

#include <Windows.h>
#include <stdio.h>
#include "pe_status.h"
#include "write_file_info.h"
#include <stdarg.h>

#include <setjmp.h>

#define WRITE_IN_FILE_BUF_SIZE 4096

CRITICAL_SECTION critical_section;
HANDLE th_event;
volatile BOOL finished;
volatile BOOL found_file;

#define TRY do{ jmp_buf ex_buf__; if( !setjmp(ex_buf__) ){
#define CATCH } else {
#define ETRY } }while(0)
#define THROW longjmp(ex_buf__, 1)

BOOL in_arr(_In_ WORD item, _In_ WORD arr[]);
PE_STATUS get_directory_name(_Out_ TCHAR directory_name[], _In_ TCHAR original_name[]);
PE_STATUS get_file_name(_Out_ TCHAR file_name[], _In_ TCHAR original_name[]);
PE_STATUS path_append(_Inout_ TCHAR original[], _In_ DWORD max_len, _In_ TCHAR to_copy[]);
TCHAR* path_to_filename(_In_ TCHAR* pathname, _In_ DWORD length);
PE_STATUS write_in_file(_Inout_ WRITE_FILE_INFO* wf, _In_ char format[], ...);
