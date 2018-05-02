#pragma once

#include <Windows.h>
#include "data_directory.h"
#include "thread_item.h"
#include "utils.h"
#include "list.h"
#include "macros.h"

#define LINE_BREAKER "=======================================\n"

PE_STATUS dump_current_directory_files(_In_ char filename[], _In_ TCHAR current_directory[], \
	_In_ BOOL recursive, _In_ BYTE no_threads, _In_ TCHAR log_directory[], _In_ LIST_ENTRY *item_list, _In_ HANDLE* threads);

PE_STATUS recurse_dump_current_directory_files(_In_ char filename[], _In_ TCHAR current_directory[], \
	_In_ WIN32_FIND_DATA* file_data, _In_ BYTE no_threads, _In_ TCHAR log_directory[], _In_ LIST_ENTRY *item_list, _In_ HANDLE* threads);

DWORD WINAPI thread_dump(void *_item_list);
