#include "dump.h"

#ifdef PE_DEBUG
	#include <stdio.h>
#endif

DWORD va2pa(_In_ DWORD address, _In_ IMAGE_SECTION_HEADER *_section_header, _In_ IMAGE_FILE_HEADER *file_header, _In_ BYTE *mapped_file)
{
	WORD i = 0;
	IMAGE_SECTION_HEADER *section_header = _section_header;

	if (address == 0)
	{
		return 0;
	}

	for (i = 0; i < file_header->NumberOfSections; i++)
	{
		if ((section_header->VirtualAddress <= address) && (address < (section_header->VirtualAddress + \
			((section_header->Misc.VirtualSize == 0) ? section_header->SizeOfRawData : section_header->Misc.VirtualSize))))
		{
			break;
		}
		++section_header;
	}

	return (DWORD)(mapped_file + section_header->PointerToRawData + (address - section_header->VirtualAddress));
}

/*
* Maps the file into memory and returns the void pointer to the start of the mapped area.
*/
LPVOID map_file_read(_In_ HANDLE file)
{
	LPVOID void_data;

	HANDLE mapped_file = CreateFileMapping(
		file, //handle
		NULL, //security
		PAGE_READONLY, //read-only
		0,
		0,
		NULL
	);

	if (mapped_file != NULL)
	{
		void_data = MapViewOfFile(
			mapped_file,
			FILE_MAP_READ,
			0,
			0,
			0
		);

		CloseHandle(mapped_file);

		if (void_data != NULL)
		{
			return void_data;
		}
	}

	return NULL;
}

PE_STATUS dump_dos_header(_In_ IMAGE_DOS_HEADER *dos_header, _In_ WIN32_FIND_DATA *file_data, _Inout_ WRITE_FILE_INFO *wf)
{
	PE_STATUS status = PE_STATUS_SUCCESS;

	PE_CHECK(write_in_file(FALSE, wf, "\t%-15s: %c%c\n", "e_magic", *((BYTE *)&dos_header->e_magic), *(((BYTE *)&dos_header->e_magic) + 1)));

	if (dos_header->e_magic != 0x5a4d) // aka "MZ"
	{
		status |= PE_STATUS_MZ_MAGIC_INVALID;
	}

	PE_CHECK(write_in_file(FALSE, wf, "\t%-15s: %#x\n", "e_lfanew", dos_header->e_lfanew));
	
	if ((DWORD)dos_header->e_lfanew >= (DWORD)(abs(file_data->nFileSizeLow - file_data->nFileSizeHigh)))
	{
		status |= PE_STATUS_LFANEW_OUT_OF_BOUNDS;
	}

	if (dos_header->e_lfanew <= 0x3c)
	{
		status |= PE_STATUS_LFANEW_OUT_OF_BOUNDS;
	}

cleanup:
	return status;
}

PE_STATUS dump_nt_signature(_In_ IMAGE_NT_HEADERS *nt_headers, _Inout_ WRITE_FILE_INFO *wf)
{
	PE_STATUS status = PE_STATUS_SUCCESS;

	if (nt_headers->Signature != 0x4550 || *(((WORD *)&(nt_headers->Signature)) + 1) != 0x0000) // aka "PE\0\0"
	{
		status |= PE_STATUS_NT_SIGNATURE_INVALID;
	}
	else
	{
		if (strlen((char *)&(nt_headers->Signature)) > 2)
		{
			return PE_STATUS_NT_SIGNATURE_INVALID;
		}

		PE_CHECK(write_in_file(FALSE, wf, "\t%-15s: %s\n", "NT Signature", ((char *)&(nt_headers->Signature))));
	}

cleanup:
	return status;
}

PE_STATUS dump_file_header(_In_ IMAGE_FILE_HEADER *file_header, _Inout_ WRITE_FILE_INFO *wf)
{
	PE_STATUS status = PE_STATUS_SUCCESS;

	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-20s: %#x\n", "Machine", file_header->Machine));

	if (file_header->Machine != IMAGE_FILE_MACHINE_I386) // aka 0x14c for 32 bit 0x8664 64bit
	{
		status |= PE_STATUS_NOT_32BIT_ONLY_EXE;
	}

	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-20s: %d\n", "NumberOfSections", file_header->NumberOfSections));

	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-20s: %#x\n", "Characteristics", file_header->Characteristics));

	if (file_header->Characteristics == 0)
	{
		status |= PE_STATUS_INVALID_CHARACTERISTICS;
	}

cleanup:
	return status;
}

PE_STATUS dump_optional_header(_In_ IMAGE_OPTIONAL_HEADER *optional_header, _Inout_ WRITE_FILE_INFO *wf)
{
	PE_STATUS status = PE_STATUS_SUCCESS;

	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-20s: %#x\n", "Magic", optional_header->Magic));
	if (optional_header->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		status |= PE_STATUS_OPTIONAL_HEADER_INVALID_SIGNATURE;
	}

	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-20s: %#x\n", "BaseOfCode", optional_header->BaseOfCode));
	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-20s: %#x\n", "BaseOfData", optional_header->BaseOfData));
	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-20s: %#x\n", "ImageBase", optional_header->ImageBase));
	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-20s: %d\n", "NumberOfRvaAndSizes", optional_header->NumberOfRvaAndSizes));

cleanup:
	return status;
}

PE_STATUS dump_section(_In_ IMAGE_SECTION_HEADER *section_header, _In_ DWORD *image_base, _Inout_ WRITE_FILE_INFO *wf)
{
	PE_STATUS status = PE_STATUS_SUCCESS;
	
	__try
	{
		if (strlen((char *)section_header->Name) > IMAGE_SIZEOF_SHORT_NAME)
		{
			return PE_STATUS_INVALID_SECTION_NAME;
		}

		if (strcmp((char *)section_header->Name, ".Adson") == 0)
		{
			return PE_STATUS_SCAN_VIRUS;
		}

		PE_CHECK(write_in_file(FALSE, wf, "\t%s\n", section_header->Name));
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return PE_STATUS_INVALID_SECTION_NAME;
	}

	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-12s: %#x\n", "ImageBase", *image_base));
	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-12s: %#x\n", "RVA", section_header->VirtualAddress));
	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-12s: %#x\n", "VA", section_header->VirtualAddress + *image_base));
	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-12s: %#x\n", "RawSize", section_header->SizeOfRawData));
	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-12s: %#X\n", "RawPointer", section_header->PointerToRawData));
	PE_CHECK(write_in_file(FALSE, wf, "\t\t%-12s: %#X\n", "VirtualSize", section_header->Misc.VirtualSize));

cleanup:
	return status;
}

PE_STATUS dump_export_directory_functions(_In_ IMAGE_EXPORT_DIRECTORY *export_directory, _In_ IMAGE_SECTION_HEADER *section_header, \
	_In_ IMAGE_FILE_HEADER *file_header, _In_ LPVOID mapped_file, _Inout_ WRITE_FILE_INFO *wf)
{
	PE_STATUS status = PE_STATUS_SUCCESS;

	DWORD i = 0;
	DWORD *a_names = (DWORD *)va2pa(export_directory->AddressOfNames, section_header, file_header, mapped_file);
	WORD *a_name_ordinals = (WORD *)va2pa(export_directory->AddressOfNameOrdinals, section_header, file_header, mapped_file);
	DWORD *a_functions = (DWORD *)va2pa(export_directory->AddressOfFunctions, section_header, file_header, mapped_file);
	IMAGE_OPTIONAL_HEADER *optional_header = (IMAGE_OPTIONAL_HEADER *)(((BYTE *)file_header) + sizeof(IMAGE_FILE_HEADER));
	
	if (export_directory->NumberOfFunctions == 0 && export_directory->NumberOfNames == 0)
	{
		status = write_in_file(FALSE, wf, "\tNo functions exported.\n");

		return status;
	}

	BOOL *apparitions_functions = NULL;

	apparitions_functions = (BOOL *)malloc(sizeof(BOOL) * export_directory->NumberOfFunctions);

	for (i = 0; i < export_directory->NumberOfFunctions; ++i)
	{
		apparitions_functions[i] = FALSE;
	}

	PE_CHECK(write_in_file(FALSE, wf, "\n\tExported functions:\n"));

	for (i = 0; i < export_directory->NumberOfNames; ++i)
	{
		DWORD a_name = va2pa(a_names[i], section_header, file_header, mapped_file);
		WORD a_name_ordinal = a_name_ordinals[i];

		if (a_name > (DWORD)mapped_file + optional_header->SizeOfImage)
		{
			return PE_STATUS_INVALID_EXPORT_DIRECTORY;
		}

		if ((DWORD)strlen((char *)a_name) > (DWORD)abs(a_name - (DWORD)mapped_file))
		{
			return PE_STATUS_INVALID_EXPORT_DIRECTORY;
		}

		PE_CHECK(write_in_file(FALSE, wf, "\t\tFunction: %s\n", (char *)a_name));
		PE_CHECK(write_in_file(FALSE, wf, "\t\t\tName ordinal: %d\n", a_name_ordinal));

		if (a_name_ordinal < export_directory->NumberOfFunctions)
		{
			DWORD a_function = a_functions[a_name_ordinal];

			PE_CHECK(write_in_file(FALSE, wf, "\t\t\tRVA: %#x\n", a_function));
			PE_CHECK(write_in_file(FALSE, wf, "\t\t\tVA:  %#x\n", a_function + optional_header->ImageBase));

			apparitions_functions[a_name_ordinal] = TRUE;
		}
		else
		{
			PE_CHECK(write_in_file(FALSE, wf, "\t\t\tNo function associated.\n"));
		}
	}

	//more functions case
	for (i = 0; i < export_directory->NumberOfFunctions; ++i)
	{
		if (!apparitions_functions[i])
		{
			PE_CHECK(write_in_file(FALSE, wf, "\t\tFunction: (NO NAME)\n"));
			PE_CHECK(write_in_file(FALSE, wf, "\t\t\tRVA: %#x\n", a_functions[i]));
			PE_CHECK(write_in_file(FALSE, wf, "\t\t\tVA:  %#x\n", a_functions[i] + optional_header->ImageBase));
		}
	}


cleanup:
	free(apparitions_functions);

	return status;
}

PE_STATUS dump_export_directory(_In_ IMAGE_EXPORT_DIRECTORY *export_directory, _In_ IMAGE_SECTION_HEADER *section_header,\
	_In_ IMAGE_FILE_HEADER *file_header, _In_ LPVOID mapped_file, _Inout_ WRITE_FILE_INFO *wf)
{
	PE_STATUS status = PE_STATUS_SUCCESS;

	CHAR *name_p = (CHAR *)va2pa(export_directory->Name, section_header, file_header, mapped_file);

	// WAY better than IsBadReadPtr
	__try
	{
		PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %s\n", "Name", name_p));
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %#x\n", "Name", export_directory->Name));
	}

	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %#x\n", "Characteristics", export_directory->Characteristics));
	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %d\n", "TimeDateStamp", export_directory->TimeDateStamp));
	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %d\n", "MajorVersion", export_directory->MajorVersion));
	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %d\n", "MinorVersion", export_directory->MinorVersion));
	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %d\n", "Base", export_directory->Base));
	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %d\n", "MinorVersion", export_directory->MinorVersion));
	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %d\n", "NumberOfFunctions", export_directory->NumberOfFunctions));
	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %d\n", "NumberOfNames", export_directory->NumberOfNames));
	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %#x\n", "AddressOfFunctions", export_directory->AddressOfFunctions));
	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %#x\n", "AddressOfNames", (DWORD)export_directory->AddressOfNames));
	PE_CHECK(write_in_file(FALSE, wf, "\t%-22s: %#x\n", "AddressOfNameOrdinals", export_directory->AddressOfNameOrdinals));
	
	status |= dump_export_directory_functions(export_directory, section_header, file_header, mapped_file, wf);

cleanup:
	return status;
}

PE_STATUS dump_import_descriptor_functions(_In_ IMAGE_IMPORT_DESCRIPTOR *import_descriptor, _In_ IMAGE_SECTION_HEADER *section_header, \
	_In_ IMAGE_FILE_HEADER *file_header, _In_ LPVOID mapped_file, _Inout_ WRITE_FILE_INFO *wf)
{
	// http://win32assembly.programminghorizon.com/pe-tut6.html good boi
	PE_STATUS status = PE_STATUS_SUCCESS;

	IMAGE_IMPORT_DESCRIPTOR *imp_desc = import_descriptor;
	IMAGE_THUNK_DATA *original_first_thunk = (IMAGE_THUNK_DATA *)va2pa(imp_desc->OriginalFirstThunk, section_header, file_header, mapped_file);
	IMAGE_THUNK_DATA *first_thunk = (IMAGE_THUNK_DATA *)va2pa(imp_desc->FirstThunk, section_header, file_header, mapped_file);

	if (imp_desc->OriginalFirstThunk != 0)
	{
		while (*((DWORD *)original_first_thunk) != 0)
		{
			IMAGE_IMPORT_BY_NAME *import_by_name = (IMAGE_IMPORT_BY_NAME *)va2pa(original_first_thunk->u1.AddressOfData, section_header, file_header, mapped_file);

			if (*((DWORD *)original_first_thunk) & IMAGE_ORDINAL_FLAG32)
			{
				PE_CHECK(write_in_file(FALSE, wf, "\t\t\t%-13s: %d %#x\n", "FunctionOrd",\
					*((DWORD *)original_first_thunk) ^ IMAGE_ORDINAL_FLAG32, *((DWORD *)original_first_thunk) ^ IMAGE_ORDINAL_FLAG32));
			}
			else
			{
				PE_CHECK(write_in_file(FALSE, wf, "\t\t\t%-13s: %s\n", "FunctionName", (char *)import_by_name->Name));
			}

			++original_first_thunk;
		}
	}
	else if (imp_desc->FirstThunk != 0)
	{
		while (*((DWORD *)first_thunk) != 0)
		{
			PE_CHECK(write_in_file(FALSE, wf, "\t\t\t%-13s: %#x\n", "FunctionRVA", *((DWORD *)first_thunk)));
			++first_thunk;
		}
	}
	else
	{
		PE_CHECK(write_in_file(FALSE, wf, "\t\t\tNo imports.\n"));
	}

cleanup:
	return status;
}


PE_STATUS dump_import_descriptor(_In_ IMAGE_IMPORT_DESCRIPTOR *import_descriptor, _In_ IMAGE_SECTION_HEADER *section_header,\
	_In_ IMAGE_FILE_HEADER *file_header, _In_ LPVOID mapped_file, _Inout_ WRITE_FILE_INFO* wf)
{
	PE_STATUS status = PE_STATUS_SUCCESS;

	IMAGE_IMPORT_DESCRIPTOR *imp_desc = import_descriptor;

	while (imp_desc->Characteristics != 0)
	{
		CHAR *name = (CHAR *)va2pa(imp_desc->Name, section_header, file_header, mapped_file);

		__try
		{
			PE_CHECK(write_in_file(FALSE, wf, "\t%-20s: %s\n", "Name", name));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status |= PE_STATUS_INVALID_NAME_RVA;
			goto cleanup;
		}

		PE_CHECK(write_in_file(FALSE, wf, "\t%-20s: %#x\n", "OriginalFirstThunk", imp_desc->OriginalFirstThunk));
		PE_CHECK(write_in_file(FALSE, wf, "\t%-20s: %d\n", "TimeDateStamp", imp_desc->TimeDateStamp));
		PE_CHECK(write_in_file(FALSE, wf, "\t%-20s: %#x\n", "ForwarderChain", imp_desc->ForwarderChain));
		PE_CHECK(write_in_file(FALSE, wf, "\t%-20s: %#x\n", "FirstThunk", imp_desc->FirstThunk));

		dump_import_descriptor_functions(imp_desc, section_header, file_header, mapped_file, wf);

		PE_CHECK(write_in_file(FALSE, wf, "\n"));

		++imp_desc;
	}

cleanup:
	return status;
}

PE_STATUS dump_file(_In_ LPVOID mapped_file, _In_ WIN32_FIND_DATA file_data, _In_ HANDLE log_file, _In_ char directoryname[])
{
	PE_STATUS status = PE_STATUS_SUCCESS;
	IMAGE_DOS_HEADER *dos_header;
	IMAGE_NT_HEADERS *nt_headers;
	IMAGE_FILE_HEADER *file_header;
	IMAGE_OPTIONAL_HEADER *optional_header;
	IMAGE_DATA_DIRECTORY *data_directory;
	IMAGE_SECTION_HEADER *section_header;
	IMAGE_EXPORT_DIRECTORY *export_directory;
	IMAGE_IMPORT_DESCRIPTOR *import_descriptor;
	WRITE_FILE_INFO wf;
	
	wf.file = log_file;
	wf.buffer_written = 0;
	wf.buffer[0] = 0;

	if (wf.file == INVALID_HANDLE_VALUE)
	{
		status = PE_STATUS_COULD_NOT_CREATE_FILE;
		goto cleanup;
	}

	//Dumping DOS header
	dos_header = (IMAGE_DOS_HEADER *)mapped_file;

	PE_CHECK(write_in_file(FALSE, &wf, "%s", "DOS header:\n"));

	PE_CHECK(dump_dos_header(dos_header, &file_data, &wf));


	//Dumping NT headers
	PE_CHECK(write_in_file(FALSE, &wf, "%s", "\nNT Headers:\n"));

	nt_headers = (IMAGE_NT_HEADERS *)((BYTE *)mapped_file + dos_header->e_lfanew);

	PE_CHECK(dump_nt_signature(nt_headers, &wf));

	PE_CHECK(write_in_file(FALSE, &wf, "%s", "\tFile Header:\n"));


	//Dumping File header
	file_header = (IMAGE_FILE_HEADER *)&(nt_headers->FileHeader);

	PE_CHECK(dump_file_header(file_header, &wf));


	//Dumping optional header
	optional_header = (IMAGE_OPTIONAL_HEADER *)&(nt_headers->OptionalHeader);

	PE_CHECK(write_in_file(FALSE, &wf, "%s", "\tOptional header:\n"));
	
	PE_CHECK(dump_optional_header(optional_header, &wf));


	//Dumping section header
	section_header = (IMAGE_SECTION_HEADER *)(((BYTE *)mapped_file) + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	PE_CHECK(write_in_file(FALSE, &wf, "%s", "\nSections:\n"));

	for (WORD i = 0; i < file_header->NumberOfSections; ++i)
	{
		PE_CHECK(dump_section(&section_header[i], &optional_header->ImageBase, &wf));
	}


	//Dumping export directory
	data_directory = (IMAGE_DATA_DIRECTORY *)&(optional_header->DataDirectory);

	export_directory = (IMAGE_EXPORT_DIRECTORY *)(va2pa(data_directory[DATA_DIRECTORY_EXPORT].VirtualAddress, section_header, file_header, mapped_file));

	PE_CHECK(write_in_file(FALSE, &wf, "%s", "\nExport Directory:\n"));

	if ((DWORD)export_directory <= (DWORD)mapped_file || \
		(DWORD)export_directory >= (DWORD)mapped_file + abs(file_data.nFileSizeHigh - file_data.nFileSizeLow) - sizeof(IMAGE_IMPORT_DESCRIPTOR))
	{
		status |= PE_STATUS_INVALID_EXPORT_DIRECTORY;
		goto cleanup;
	}

	if (!export_directory)
	{
		PE_CHECK(write_in_file(FALSE, &wf, "%s", "\tNo exports.\n"));
	}
	else
	{
		PE_CHECK(dump_export_directory(export_directory, section_header, file_header, mapped_file, &wf));
	}


	//Dumping import descriptor
	import_descriptor = (IMAGE_IMPORT_DESCRIPTOR *)(va2pa(data_directory[DATA_DIRECTORY_IMPORT].VirtualAddress, section_header, file_header, mapped_file));

	PE_CHECK(write_in_file(FALSE, &wf, "%s", "\nImport Descriptor:\n"));

	if ((DWORD)import_descriptor <= (DWORD)mapped_file ||\
		(DWORD)import_descriptor >= (DWORD)mapped_file + abs(file_data.nFileSizeHigh - file_data.nFileSizeLow))
	{
		status |= PE_STATUS_INVALID_IMPORT_DESCRIPTOR;
		goto cleanup;
	}

	if (!import_descriptor)
	{
		PE_CHECK(write_in_file(FALSE, &wf, "%s", "\tNo imports.\n"));
	}
	else
	{
		PE_CHECK(dump_import_descriptor(import_descriptor, section_header, file_header, mapped_file, &wf));
	}

cleanup:
	if (status & PE_STATUS_MZ_MAGIC_INVALID)
	{
		status |= write_in_file(FALSE, &wf, "%s", "error: dos magic is not MZ\n");
	}

	if (status & PE_STATUS_LFANEW_OUT_OF_BOUNDS)
	{
		status |= write_in_file(FALSE, &wf, "%s", "error: lfanew out of bounds.\n");
	}

	if (status & PE_STATUS_NT_SIGNATURE_INVALID)
	{
		status |= write_in_file(FALSE, &wf, "%s", "error: PE\\0\\0 signature missing.\n");
	}

	if (status & PE_STATUS_NOT_32BIT_ONLY_EXE)
	{
		status |= write_in_file(FALSE, &wf, "%s", "error: not a 32 bit ONLY exe.\n");
	}

	if (status & PE_STATUS_INVALID_CHARACTERISTICS)
	{
		status |= write_in_file(FALSE, &wf, "%s", "error: characteristics invalid.\n");
	}

	if (status & PE_STATUS_OPTIONAL_HEADER_INVALID_SIGNATURE)
	{
		status |= write_in_file(FALSE, &wf, "%s", "error: not a 32 bit magic.\n");
	}

	if (status & PE_STATUS_SCAN_VIRUS)
	{
		status |= write_in_file(TRUE, &wf, "%s\\%s : %s\n", directoryname, file_data.cFileName, "infected Virus:Win32/Adson");
		printf("%s\\%s : %s\n", directoryname, file_data.cFileName, "infected Virus:Win32/Adson");
	}
	else
	{
		status |= write_in_file(TRUE, &wf, "%s\\%s : %s\n", directoryname, file_data.cFileName, "clean");
		printf("%s\\%s : %s\n", directoryname, file_data.cFileName, "clean");
	}

	wf.buffer_written = BUFFER_SIZE;
	write_in_file(TRUE, &wf, "%s", "");

	return status;
}

PE_STATUS thread_scan_file(THREAD_ITEM *thread_item)
{
	PE_STATUS status = PE_STATUS_SUCCESS;
	WIN32_FIND_DATA file_data;
	char file_to_read[MAX_PATH] = { 0 };

	strcpy_s(file_to_read, MAX_PATH, thread_item->directoryname);
	path_append(file_to_read, MAX_PATH, thread_item->file_data.cFileName);

	HANDLE read_file = CreateFile(
		file_to_read,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_READONLY,
		NULL
	);

	if (read_file == INVALID_HANDLE_VALUE)
	{
		status |= PE_STATUS_COULD_NOT_OPEN_FILE;
		goto cleanup;
	}

	FindClose(FindFirstFile(file_to_read, &file_data)); //get_file_data

	LPVOID mapped_data = map_file_read(read_file);

	if (mapped_data == NULL)
	{
		status |= PE_STATUS_COULD_NOT_MAP_FILE;
		goto cleanup;
	}

	status |= dump_file(mapped_data, file_data, thread_item->scan_file, thread_item->directoryname);

cleanup:
	if (!(status & PE_STATUS_COULD_NOT_OPEN_FILE))
	{
		CloseHandle(read_file);
	}

	if (!(status & PE_STATUS_COULD_NOT_MAP_FILE))
	{
		UnmapViewOfFile(mapped_data);
	}

	return status;
}

PE_STATUS recurse_scan_current_directory_files(_In_ char filename[], _In_ TCHAR current_directory[],\
	_In_ WIN32_FIND_DATA* file_data, _In_ BYTE no_threads, _In_ LIST_ENTRY *item_list, _In_ HANDLE* threads, _In_ HANDLE scan_file)
{
	PE_STATUS status = PE_STATUS_SUCCESS;

	BOOL next;

	HANDLE file_find = FindFirstFile(
		"*",
		file_data
	);

	do
	{
		if (file_data->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY\
			&& strcmp(file_data->cFileName, ".")\
			&& strcmp(file_data->cFileName, ".."))
		{
			TCHAR foldername[MAX_PATH] = { 0 };
			strcpy_s(foldername, MAX_PATH, current_directory);
			path_append(foldername, MAX_PATH, file_data->cFileName);

			scan_current_directory_files(filename, foldername, TRUE, no_threads, item_list, threads, scan_file);
		}

		next = FindNextFile(
			file_find,
			file_data
		);
	} while (next);

	FindClose(file_find);

	return status;
}

PE_STATUS scan_current_directory_files(_In_ char filename[], _In_ TCHAR current_directory[], _In_ BOOL recursive,\
	_In_ BYTE no_threads, _In_ LIST_ENTRY *item_list, _In_ HANDLE* threads, _In_ HANDLE scan_file)
{
	PE_STATUS status = PE_STATUS_SUCCESS;

	HANDLE file_find;
	WIN32_FIND_DATA file_data;
	BOOL next;

	BOOL set_directory_return = SetCurrentDirectory(current_directory);

	if (set_directory_return == 0)
	{
		status = PE_STATUS_SET_DIRECTORY_FAILED;
	}

	file_find = FindFirstFile(
		filename,
		&file_data
	);

	if (file_find != INVALID_HANDLE_VALUE)
	{
		found_file = TRUE;
		do
		{
			if (file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				goto next;
			}

			THREAD_ITEM* thread_item;
			thread_item = (THREAD_ITEM *)malloc(sizeof(THREAD_ITEM));

			thread_item->scan_file = scan_file;
			strcpy_s(thread_item->directoryname, MAX_PATH, current_directory);
			thread_item->file_data = file_data;
			
			InsertTailList(item_list, &thread_item->list_entry);
			SetEvent(th_event);

		next:
			next = FindNextFile(
				file_find,
				&file_data
			);
		} while (next);

		FindClose(file_find);
	}

	if (recursive)
	{
		recurse_scan_current_directory_files(filename, current_directory, &file_data, no_threads, item_list, threads, scan_file);
	}

	return PE_STATUS_SUCCESS;
}

DWORD WINAPI thread_dump(void* _item_list)
{
	LIST_ENTRY *item_list = (LIST_ENTRY *)_item_list;
	LIST_ENTRY *l = NULL;

	while (1)
	{
		while (InterlockedIsListEmpty(item_list, &critical_section))
		{
			if (finished == TRUE)
			{
				ExitThread(0);
			}

			WaitForSingleObject(th_event, INFINITE);
		}

		ResetEvent(&th_event);

		l = InterlockedRemoveHeadList(item_list, &critical_section);

		if (l == item_list)
		{
			continue;
		}

		THREAD_ITEM* p = CONTAINING_RECORD(l, THREAD_ITEM, list_entry);

		thread_scan_file(p);

		free(p);

		if (!InterlockedIsListEmpty(item_list, &critical_section))
		{
			SetEvent(&th_event);
		}
	}

	ExitThread(0);
}
