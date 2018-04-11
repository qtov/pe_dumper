#include "dump.h"
#include "pe_status.h"
#include "data_directory.h"

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
		if ((section_header->VirtualAddress <= address) && (address < (section_header->VirtualAddress + section_header->Misc.VirtualSize)))
		{
			break;
		}
		++section_header;
	}

	return (DWORD)(mapped_file + section_header->PointerToRawData + (address - section_header->VirtualAddress));
}

LPVOID map_file(_In_ HANDLE file)
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

		if (void_data != NULL)
		{
			return void_data;
		}
	}

	return NULL;
}

PE_STATUS dump_dos_header(_In_ IMAGE_DOS_HEADER *dos_header, _In_ WIN32_FIND_DATA *file_data)
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	if (printf("\t%c%c -> e_magic\n", *((BYTE *)&dos_header->e_magic), *(((BYTE *)&dos_header->e_magic) + 1)) < 0)
	{
		ret |= PE_STATUS_PRINTF_ERROR;
	}

	if (dos_header->e_magic != 0x5a4d) // aka "MZ"
	{
		ret |= PE_STATUS_MZ_MAGIC_INVALID;
	}

	if (printf("\t%#010x -> e_lfanew\n", dos_header->e_lfanew) < 0)
	{
		ret |= PE_STATUS_PRINTF_ERROR;
	}

	if (dos_header->e_lfanew >= (abs(file_data->nFileSizeLow - file_data->nFileSizeHigh)))
	{
		ret |= PE_STATUS_LFANEW_OUT_OF_BOUNDS;
	}

	return ret;
}

PE_STATUS dump_nt_signature(_In_ IMAGE_NT_HEADERS *nt_headers)
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	if (nt_headers->Signature != 0x4550 || *(((WORD *)&(nt_headers->Signature)) + 1) != 0x0000) // aka "PE\0\0"
	{
		ret |= PE_STATUS_NT_SIGNATURE_INVALID;
	}
	else
	{
		printf("\t%s -> NT Signature\n", ((char *)&(nt_headers->Signature)));
	}

	return ret;
}

PE_STATUS dump_file_header(_In_ IMAGE_FILE_HEADER *file_header)
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	printf("\t\t%#x -> Machine\n", file_header->Machine);

	if (file_header->Machine != IMAGE_FILE_MACHINE_I386) // aka 0x14c
	{
		ret |= PE_STATUS_NOT_32BIT_ONLY_EXE;
	}

	printf("\t\t%d -> Number of sections.\n", file_header->NumberOfSections);

	printf("\t\t%#x -> Characteristics.\n", file_header->Characteristics);

	if (file_header->Characteristics == 0)
	{
		ret |= PE_STATUS_INVALID_CHARACTERISTICS;
	}

	return ret;
}

PE_STATUS dump_optional_header(_In_ IMAGE_OPTIONAL_HEADER *optional_header)
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	printf("\t\t%#x -> Magic\n", optional_header->Magic);
	if (optional_header->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		ret |= PE_STATUS_OPTIONAL_HEADER_INVALID_SIGNATURE;
	}

	printf("\t\t%#x -> Base of Code\n", optional_header->BaseOfCode);
	printf("\t\t%#x -> Base of Data\n", optional_header->BaseOfData);
	printf("\t\t%#x -> ImageBase\n", optional_header->ImageBase);
	printf("\t\t%d -> NumberOfRvaAndSizes\n", optional_header->NumberOfRvaAndSizes);

	return ret;
}

PE_STATUS dump_section(_In_ IMAGE_SECTION_HEADER *section_header, _In_ DWORD *image_base)
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	printf("\t%s\n", section_header->Name);
	printf("\t\tImageBase: %#x\n", *image_base);
	printf("\t\tRVA: %#x\n", section_header->VirtualAddress);
	printf("\t\tVA: %#x\n", section_header->VirtualAddress + *image_base);
	printf("\t\tsize: %#x\n", section_header->SizeOfRawData);

	return ret;
}

PE_STATUS dump_export_directory_functions(_In_ IMAGE_EXPORT_DIRECTORY *export_directory, _In_ IMAGE_SECTION_HEADER *section_header, _In_ IMAGE_FILE_HEADER *file_header, _In_ LPVOID mapped_file)
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	DWORD i = 0;
	DWORD *a_names = (DWORD *)va2pa(export_directory->AddressOfNames, section_header, file_header, mapped_file);
	WORD *a_name_ordinals = (WORD *)va2pa(export_directory->AddressOfNameOrdinals, section_header, file_header, mapped_file);
	DWORD *a_functions = (DWORD *)va2pa(export_directory->AddressOfFunctions, section_header, file_header, mapped_file);
	IMAGE_OPTIONAL_HEADER *optional_header = (IMAGE_OPTIONAL_HEADER *)((BYTE *)file_header) + sizeof(IMAGE_FILE_HEADER);
	
	if (export_directory->NumberOfFunctions == 0 && export_directory->NumberOfNames == 0)
	{
		printf("\tNo functions exported.\n");
		return ret;
	}

	BOOL *apparitions_functions = NULL;

	apparitions_functions = (BOOL *)malloc(sizeof(BOOL) * export_directory->NumberOfFunctions);

	for (i = 0; i < export_directory->NumberOfFunctions; ++i)
	{
		apparitions_functions[i] = FALSE;
	}

	printf("\n\tExported functions:\n");	

	for (i = 0; i < export_directory->NumberOfNames; ++i)
	{
		DWORD a_name = va2pa(a_names[i], section_header, file_header, mapped_file);
		WORD a_name_ordinal = a_name_ordinals[i];

		printf("\t\tFunction: %s\n", (char *)a_name);
		printf("\t\t\tName ordinal: %d\n", a_name_ordinal);

		if (a_name_ordinal < export_directory->NumberOfFunctions)
		{
			DWORD a_function = a_functions[a_name_ordinal];

			printf("\t\t\tRVA: %#x\n", a_function);
			printf("\t\t\tVA:  %#x\n", a_function + optional_header->ImageBase);

			apparitions_functions[a_name_ordinal] = TRUE;
		}
		else
		{
			printf("\t\t\tNo function associated.\n");
		}
	}

	//more functions case
	for (i = 0; i < export_directory->NumberOfFunctions; ++i)
	{
		if (!apparitions_functions[i])
		{
			printf("\t\tFunction: (NO NAME)\n");
			printf("\t\t\tRVA: %#x\n", a_functions[i]);
			printf("\t\t\tVA:  %#x\n", a_functions[i] + optional_header->ImageBase);
		}
	}

	return ret;
}

PE_STATUS dump_export_directory(_In_ IMAGE_EXPORT_DIRECTORY *export_directory, _In_ IMAGE_SECTION_HEADER *section_header, _In_ IMAGE_FILE_HEADER *file_header, _In_ LPVOID mapped_file)
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	printf("\t%s -> Name\n", (CHAR *)va2pa(export_directory->Name, section_header, file_header, mapped_file));
	printf("\t%#x -> Characteristics\n", export_directory->Characteristics);
	printf("\t%d -> TimeDateStamp\n", export_directory->TimeDateStamp);
	printf("\t%d -> MajorVersion\n", export_directory->MajorVersion);
	printf("\t%d -> MinorVersion\n", export_directory->MinorVersion);
	printf("\t%d -> Base\n", export_directory->Base);
	printf("\t%d -> MinorVersion\n", export_directory->MinorVersion);
	printf("\t%d -> NumberOfFunctions\n", export_directory->NumberOfFunctions);
	printf("\t%d -> NumberOfNames\n", export_directory->NumberOfNames);
	printf("\t%#x -> AddressOfFunctions\n", export_directory->AddressOfFunctions);
	printf("\t%#x -> AddressOfNames\n", export_directory->AddressOfNames);
	printf("\t%#x -> AddressOfNameOrdinals\n", export_directory->AddressOfNameOrdinals);
	
	ret |= dump_export_directory_functions(export_directory, section_header, file_header, mapped_file);

	return ret;
}

PE_STATUS dump_import_descriptor_functions(_In_ IMAGE_IMPORT_DESCRIPTOR *import_descriptor, _In_ IMAGE_SECTION_HEADER *section_header, _In_ IMAGE_FILE_HEADER *file_header, _In_ LPVOID mapped_file)
{
	// http://win32assembly.programminghorizon.com/pe-tut6.html good boi
	PE_STATUS ret = PE_STATUS_SUCCESS;

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
				printf("\t\t\t%13s %d %#x\n", "FunctionOrd:", *((DWORD *)original_first_thunk) ^ IMAGE_ORDINAL_FLAG32, *((DWORD *)original_first_thunk) ^ IMAGE_ORDINAL_FLAG32);
			}
			else
			{
				printf("\t\t\t%13s %s\n", "FunctionName:", (char *)import_by_name->Name);
			}

			++original_first_thunk;
		}
	}
	else if (imp_desc->FirstThunk != 0)
	{
		while (*((DWORD *)first_thunk) != 0)
		{
			printf("\t\t\t%13s %#x\n", "FunctionRVA:", *((DWORD *)first_thunk));
			++first_thunk;
		}
	}
	else
	{
		printf("\t\t\tNo imports.\n");
	}

	return ret;
}


PE_STATUS dump_import_descriptor(_In_ IMAGE_IMPORT_DESCRIPTOR *import_descriptor, _In_ IMAGE_SECTION_HEADER *section_header, _In_ IMAGE_FILE_HEADER *file_header, _In_ LPVOID mapped_file)
{
	PE_STATUS ret = PE_STATUS_SUCCESS;

	IMAGE_IMPORT_DESCRIPTOR *imp_desc = import_descriptor;

	while (imp_desc->Characteristics != 0)
	{
		CHAR *name = (CHAR *)va2pa(imp_desc->Name, section_header, file_header, mapped_file);

		printf("\t%20s\t%s\n", "Name:", name);
		printf("\t%20s\t%#x\n", "OriginalFirstThunk:", imp_desc->OriginalFirstThunk);
		printf("\t%20s\t%d\n", "TimeDateStamp:", imp_desc->TimeDateStamp);
		printf("\t%20s\t%#x\n", "ForwarderChain:", imp_desc->ForwarderChain);
		printf("\t%20s\t%#x\n", "FirstThunk:", imp_desc->FirstThunk);

		dump_import_descriptor_functions(imp_desc, section_header, file_header, mapped_file);

		printf("\n");

		++imp_desc;
	}

	return ret;
}

void dump_mapped_file(_In_ LPVOID mapped_file, _In_ WIN32_FIND_DATA* file_data)
{
	PE_STATUS status;
	IMAGE_DOS_HEADER *dos_header;
	IMAGE_NT_HEADERS *nt_headers;
	IMAGE_FILE_HEADER *file_header;
	IMAGE_OPTIONAL_HEADER *optional_header;
	IMAGE_DATA_DIRECTORY *data_directory;
	IMAGE_SECTION_HEADER *section_header;
	IMAGE_EXPORT_DIRECTORY *export_directory;
	IMAGE_IMPORT_DESCRIPTOR *import_descriptor;

	dos_header = (IMAGE_DOS_HEADER *)mapped_file;

	printf("DOS header:\n");

	if ((status = dump_dos_header(dos_header, file_data)) != PE_STATUS_SUCCESS)
	{
		goto cleanup;
	}

	printf("\nNT Headers:\n");
	nt_headers = (IMAGE_NT_HEADERS *)((BYTE *)mapped_file + dos_header->e_lfanew);

	if ((status = dump_nt_signature(nt_headers)) != PE_STATUS_SUCCESS)
	{
		goto cleanup;
	}

	printf("\tFile Header:\n");
	file_header = (IMAGE_FILE_HEADER *)&(nt_headers->FileHeader);

	if ((status = dump_file_header(file_header)) != PE_STATUS_SUCCESS)
	{
		goto cleanup;
	}

	optional_header = (IMAGE_OPTIONAL_HEADER *)&(nt_headers->OptionalHeader);

	printf("\tOptional header:\n");

	if ((status = dump_optional_header(optional_header)) != PE_STATUS_SUCCESS)
	{
		goto cleanup;
	}

	section_header = (IMAGE_SECTION_HEADER *)(((BYTE *)mapped_file) + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	printf("\nSections:\n");

	for (WORD i = 0; i < file_header->NumberOfSections; ++i)
	{
		if ((status = dump_section(&section_header[i], &optional_header->ImageBase)) != PE_STATUS_SUCCESS)
		{
			goto cleanup;
		}
	}

	data_directory = (IMAGE_DATA_DIRECTORY *)&(optional_header->DataDirectory);

	export_directory = (IMAGE_EXPORT_DIRECTORY *)(va2pa(data_directory[DATA_DIRECTORY_EXPORT].VirtualAddress, section_header, file_header, mapped_file));

	printf("\nExport Directory:\n");

	if (!export_directory)
	{
		printf("\tNo exports.\n");
	}
	else if ((status = dump_export_directory(export_directory, section_header, file_header, mapped_file)) != PE_STATUS_SUCCESS)
	{
		goto cleanup;
	}

	import_descriptor = (IMAGE_IMPORT_DESCRIPTOR *)(va2pa(data_directory[DATA_DIRECTORY_IMPORT].VirtualAddress, section_header, file_header, mapped_file));

	printf("\nImport Descriptor:\n");
	if (!import_descriptor)
	{
		printf("\tNo imports.\n");
	}
	else if ((status = dump_import_descriptor(import_descriptor, section_header, file_header, mapped_file)) != PE_STATUS_SUCCESS)
	{
		goto cleanup;
	}

cleanup:
	if (status & PE_STATUS_MZ_MAGIC_INVALID)
	{
		printf("error: dos magic is not MZ\n");
	}

	if (status & PE_STATUS_LFANEW_OUT_OF_BOUNDS)
	{
		printf("error: lfanew out of bounds.\n");
	}

	if (status & PE_STATUS_NT_SIGNATURE_INVALID)
	{
		printf("error: PE\\0\\0 signature missing.\n");
	}

	if (status & PE_STATUS_NOT_32BIT_ONLY_EXE)
	{
		printf("error: not a 32 bit ONLY exe.\n");
	}

	if (status & PE_STATUS_INVALID_CHARACTERISTICS)
	{
		printf("error: characteristics invalid.\n");
	}

	if (status & PE_STATUS_OPTIONAL_HEADER_INVALID_SIGNATURE)
	{
		printf("error: Not a 32 bit magic.\n");
	}
}

void recurse_dump_current_directory_files(_In_ char filename[], _In_ TCHAR current_directory[], _In_ WIN32_FIND_DATA* file_data)
{
	BOOL next;

	HANDLE file_find = FindFirstFile(
		"*",
		file_data
	);

	do
	{
		if (file_data->dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY\
			&& strcmp(file_data->cFileName, ".")\
			&& strcmp(file_data->cFileName, ".."))
		{
			TCHAR foldername[MAX_PATH] = { 0 };
			strcat_s(foldername, MAX_PATH, current_directory);
			strcat_s(foldername, MAX_PATH, "\\");
			strcat_s(foldername, MAX_PATH, file_data->cFileName);

			dump_current_directory_files(filename, foldername, TRUE);
		}

		next = FindNextFile(
			file_find,
			file_data
		);
	} while (next);
}

void dump_current_directory_files(_In_ char filename[], _In_ TCHAR current_directory[], _In_ BOOL recursive)
{
	HANDLE file;
	HANDLE file_find;
	WIN32_FIND_DATA file_data;
	BOOL next;

	SetCurrentDirectory(current_directory);

	file_find = FindFirstFile(
		filename,
		&file_data
	);

	printf("\n\n");
	printf("%s:\n", current_directory);
	printf(LINE_BREAKER);

	if (file_find != INVALID_HANDLE_VALUE)
	{
		do
		{
			file = CreateFile(
				file_data.cFileName,
				GENERIC_READ,
				FILE_SHARE_READ,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_READONLY,
				NULL
			);

			if (GetLastError() == ERROR_FILE_NOT_FOUND)
			{
				goto next;
			}

			printf("---> %s\n\n", file_data.cFileName);

			LPVOID mapped_file = map_file(file);

			if (mapped_file != NULL)
			{
				dump_mapped_file(mapped_file, &file_data);
				UnmapViewOfFile(mapped_file);
			}
			else
			{
				printf("Error mapping.\n");
			}

			printf(LINE_BREAKER);

			CloseHandle(file);

		next:
			next = FindNextFile(
				file_find,
				&file_data
			);
		} while (next);
	}

	if (recursive)
	{
		recurse_dump_current_directory_files(filename, current_directory, &file_data);
	}
}