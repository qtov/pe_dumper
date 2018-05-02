#pragma once

#include <Windows.h>
#include "data_directory.h"
#include "thread_item.h"
#include "utils.h"
#include "list.h"
#include "macros.h"

#define LINE_BREAKER "=======================================\n"

PE_STATUS scan_current_directory_files(_In_ char filename[], _In_ TCHAR current_directory[], \
	_In_ BOOL recursive, _In_ BYTE no_threads, _In_ LIST_ENTRY *item_list, _In_ HANDLE* threads, _In_ HANDLE scan_file);

PE_STATUS recurse_scan_current_directory_files(_In_ char filename[], _In_ TCHAR current_directory[], \
	_In_ WIN32_FIND_DATA* file_data, _In_ BYTE no_threads, _In_ LIST_ENTRY *item_list, _In_ HANDLE* threads, _In_ HANDLE scan_file);

DWORD WINAPI thread_dump(void *_item_list);
