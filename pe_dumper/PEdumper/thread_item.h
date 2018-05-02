#pragma once

#include "list.h"

typedef struct
{
	WIN32_FIND_DATA file_data;
	char directoryname[MAX_PATH];
	HANDLE scan_file;

	LIST_ENTRY list_entry;
} THREAD_ITEM;