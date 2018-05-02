#pragma once

#include <Windows.h>

#define BUFFER_SIZE 4500

typedef struct
{
	HANDLE	file;
	char	buffer[BUFFER_SIZE];
	DWORD	buffer_written;

} WRITE_FILE_INFO;