#include "utils.h"
#ifdef PE_DEBUG
	#include <stdio.h>
#endif

BOOL in_arr(_In_ WORD item, _In_ WORD arr[])
{
	WORD* p = arr;

	while (*p)
	{
		if (*p == item)
		{
			return TRUE;
		}
		++p;
	}

	return FALSE;
}

BOOL is_char_folder(_In_ TCHAR chr)
{
	if ((chr >= 'a' && chr <= 'z') || (chr >= 'A' && chr <= 'Z') \
		|| (chr >= '0' && chr <= '9') || (chr == '.') || (chr == '?') || (chr == '*'))
	{
		return TRUE;
	}

	return FALSE;
}

PE_STATUS get_directory_name(_Out_ TCHAR directory_name[], _In_ TCHAR original_name[])
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	BOOL was = FALSE;
	int len = strlen(original_name);

	if (original_name[len - 1] == '\\' || original_name[len - 1] == '/')
	{
		return PE_STATUS_INVALID_PATH_ARGUMENT;
	}

	for (int i = len - 2; i >= 0; --i)
	{
		if (!was && (original_name[i] == '\\' || original_name[i] == '/'))
		{
			was = TRUE;
			directory_name[i] = 0;
			continue;
		}

		if (was)
		{
			directory_name[i] = original_name[i];
		}
	}

	if (!was)
	{
		GetCurrentDirectory(
			4096,
			directory_name
		);
	}

	int lens = strlen(directory_name);

	strcat_s(directory_name, lens + 3, "\\."); //drive problems
	//aka "C:/" doesn't work but "C:/./" does work, weird

	return ret;
}

PE_STATUS get_file_name(_Out_ TCHAR file_name[], _In_ TCHAR original_name[])
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	int len = strlen(original_name);

	if (original_name[len - 1] == '\\' || original_name[len - 1] == '/')
	{
		return PE_STATUS_INVALID_PATH_ARGUMENT;
	}

	int i = len - 1;
	while (i >= 0 && original_name[i] != '/' && original_name[i] != '\\')
	{
		--i;
	}
	++i;

	int j = 0;
	
	for (; i < len; ++i)
	{
		file_name[j] = original_name[i];
		++j;
	}

	file_name[j] = 0;
	
	return ret;
}

PE_STATUS validate_path(char str[])
{
	PE_STATUS ret = PE_STATUS_SUCCESS;
	TCHAR foldername[256];
	TCHAR filename[256];

	ret |= get_directory_name(foldername, str);

	ret |= get_file_name(filename, str);

	BOOL set_directory_return = SetCurrentDirectory(foldername);

	if (set_directory_return == 0)
	{
		ret |= PE_STATUS_INVALID_PATH_ARGUMENT;
	}

	size_t len = strlen(filename);

	for (int i = len - 1; i >= 0; --i)
	{
		if (!is_char_folder(filename[i]))
		{
			return PE_STATUS_INVALID_PATH_ARGUMENT;
		}
	}

	return ret;
}
