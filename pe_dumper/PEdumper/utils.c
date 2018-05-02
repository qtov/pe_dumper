#include "utils.h"

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

BOOL is_char_valid_filename(_In_ TCHAR chr)
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

	if (len > MAX_PATH)
	{
		return PE_STATUS_PATH_OUT_OF_RANGE;
	}

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
		//TCHAR dir[MAX_PATH];

		if (SetCurrentDirectory(directory_name) == 0)
		{
			return PE_STATUS_INVALID_PATH_ARGUMENT;
		}

		GetCurrentDirectory(MAX_PATH, directory_name);

		//strcpy_s(directory_name, strlen(dir) + 1, dir);
	}

	if (!was)
	{
		// For relative path, get absolute path.
		GetCurrentDirectory(
			MAX_PATH,
			directory_name
		);
	}

	// Drive problems
	// aka "C:/" doesn't work but "C:/./" does.
	strcat_s(directory_name, strlen(directory_name) + 3, "\\.");

	if (SetCurrentDirectory(directory_name) == 0)
	{
		return PE_STATUS_INVALID_PATH_ARGUMENT;
	}

	return ret;
}

PE_STATUS get_file_name(_Out_ TCHAR file_name[], _In_ TCHAR original_name[])
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	int len = strlen(original_name);

	if (len > MAX_PATH)
	{
		return PE_STATUS_PATH_OUT_OF_RANGE;
	}

	// If filename ends in / or \ it's not a file but a directory.
	if (original_name[len - 1] == '\\' || original_name[len - 1] == '/')
	{
		return PE_STATUS_INVALID_PATH_ARGUMENT;
	}

	// Find the start of the last / or \ to start copying from there the filename.
	signed int i = len - 1;
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

PE_STATUS path_append(_Inout_ TCHAR original[], _In_ DWORD max_len, _In_ TCHAR to_copy[])
{
	int len = strlen(original);

	if (strlen(original) + strlen(to_copy) >= max_len)
	{
		return PE_STATUS_PATH_OUT_OF_RANGE;
	}

	if (original[len - 1] != '/' && original[len - 1] != '\\')
	{
		strcat_s(original, max_len, "\\");
	}

	strcat_s(original, max_len, to_copy);

	if (strlen(original) > max_len)
	{
		return PE_STATUS_PATH_OUT_OF_RANGE;
	}

	return PE_STATUS_SUCCESS;
}

TCHAR* path_to_filename(_In_ TCHAR* pathname, _In_ DWORD length)
{
	int n = strlen(pathname);
	TCHAR *new_str;

	new_str = (TCHAR *)malloc(sizeof(TCHAR) * (length + 1));

	int j = 0;

	for (int i = 0; i < n; ++i)
	{
		if ((pathname[i + 1] == '/' || pathname[i + 1] == '\\') && (pathname[i] == '.')) //aka ./ Cause... I'm adding it + a directory cannot have such a name.
		{
			++i;
			continue; //this case skip two
		}

		if (pathname[i] == '/' || pathname[i] == '\\' || pathname[i] == ':')
		{
			new_str[j] = '_';
		}
		else
		{
			new_str[j] = pathname[i];
		}
		++j;
	}

	new_str[j] = 0;

	return new_str;
}

PE_STATUS write_in_file(_Inout_ WRITE_FILE_INFO* wf, _In_ char format[], ...)
{
	char buf[WRITE_IN_FILE_BUF_SIZE] = { 0 };
	BOOL write_file;
	va_list args;
	va_start(args, format);

	int bytes_written = vsnprintf_s(buf, WRITE_IN_FILE_BUF_SIZE, WRITE_IN_FILE_BUF_SIZE, format, args);

	if (bytes_written + wf->buffer_written > BUFFER_SIZE)
	{
		write_file = WriteFile(
			wf->file,
			wf->buffer,
			strlen(wf->buffer),
			NULL,
			NULL
		);

		if (!write_file)
		{
			return PE_STATUS_COULD_NOT_WRITE_IN_FILE;
		}

		wf->buffer_written = 0;
	}

	if (wf->buffer_written == 0)
	{
		strcpy_s(wf->buffer, BUFFER_SIZE, buf);
	}
	else if (wf->buffer_written < 4000)
	{
		strcat_s(wf->buffer, BUFFER_SIZE, buf);
	}
	else
	{
		strcat_s(wf->buffer, BUFFER_SIZE, buf);

		write_file = WriteFile(
			wf->file,
			wf->buffer,
			strlen(wf->buffer),
			NULL,
			NULL
		);

		wf->buffer_written = 0;

		if (write_file)
		{
			return PE_STATUS_SUCCESS;
		}
		else
		{
			return PE_STATUS_COULD_NOT_WRITE_IN_FILE;
		}
	}

	wf->buffer_written += bytes_written;

	return PE_STATUS_SUCCESS;
}
