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

	// If it ends in / or \ or . it means there was no file specified.
	// Aka the program refuses to work with files like name. or name1.
	if (original_name[len - 1] == '\\' || original_name[len - 1] == '/' || original_name[len - 1] == '.')
	{
		return PE_STATUS_INVALID_PATH_ARGUMENT;
	}

	for (signed int i = len - 2; i >= 0; --i)
	{
		// Find where the / or \ are and take path from there downwards.
		if (!was && (original_name[i] == '\\' || original_name[i] == '/'))
		{
			was = TRUE;
			directory_name[i] = 0;

			continue;
		}

		// The actual copy.
		if (was)
		{
			// Change / to \ just to have a cleaner look.
			if (original_name[i] == '/')
			{
				directory_name[i] = '\\';
			}
			else
			{
				directory_name[i] = original_name[i];
			}
		}
	}

	// If directory name starts with . or / or \ then try to set it and go there.
	// For case when it's ../something to transform into absolute path.
	if (directory_name[0] == '.' || directory_name[0] == '/' || directory_name[0] == '\\')
	{
		TCHAR dir[MAX_PATH];

		if (SetCurrentDirectory(directory_name) == 0)
		{
			return PE_STATUS_INVALID_PATH_ARGUMENT;
		}

		GetCurrentDirectory(MAX_PATH, dir);

		strcpy_s(directory_name, strlen(dir) + 1, dir);
	}

	if (!was)
	{
		// For relative path, get absolute path.
		GetCurrentDirectory(
			4096,
			directory_name
		);
	}

	// Drive problems
	// aka "C:/" doesn't work but "C:/./" does.
	strcat_s(directory_name, strlen(directory_name) + 3, "\\.");

	return ret;
}

PE_STATUS get_file_name(_Out_ TCHAR file_name[], _In_ TCHAR original_name[])
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	int len = strlen(original_name);

	// If filename ends in / or \ it's not a file but directory.
	if (original_name[len - 1] == '\\' || original_name[len - 1] == '/')
	{
		return PE_STATUS_INVALID_PATH_ARGUMENT;
	}

	// Find the start of the last / or \ to start copying from there the filename.
	int i = len - 1;
	while (i >= 0 && original_name[i] != '/' && original_name[i] != '\\')
	{
		--i;
	}
	++i; // i stops at / or \ which is not in the filename.

	int j = 0;
	
	// Kind of strcpy.
	for (; i < len; ++i)
	{
		file_name[j] = original_name[i];
		++j;
	}

	// Ending character.
	file_name[j] = 0;
	
	return ret;
}

// Unnecessary most probably, will look into it later.
PE_STATUS validate_path(_In_ char str[])
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
