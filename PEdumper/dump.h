#pragma once

#include <Windows.h>
#include <stdio.h>

#define LINE_BREAKER "=======================================\n"

void dump_current_directory_files(char filename[], TCHAR current_directory[], BOOL recursive);
void recurse_dump_current_directory_files(char filename[], TCHAR current_directory[], WIN32_FIND_DATA* file_data);