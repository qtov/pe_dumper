#pragma once

#include "list.h"

typedef struct
{
	WIN32_FIND_DATA file_data;
	char directoryname[MAX_PATH];
	char log_file[MAX_PATH];

	LIST_ENTRY list_entry;
} THREAD_ITEM;