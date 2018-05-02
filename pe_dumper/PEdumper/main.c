#include "main.h"
#include "dump.h"
#include "utils.h"
#ifdef PE_DEBUG
	#include <time.h>
#endif

PE_STATUS initialize_threads(_Out_ HANDLE **threads, _In_ DWORD no_threads, _In_ PLIST_ENTRY item_list)
{
	PE_STATUS ret = PE_STATUS_SUCCESS;
	int i = 0;

	*threads = (HANDLE *)malloc(sizeof(HANDLE) * no_threads);

	for (i = 0; i < (signed __int64)no_threads; ++i)
	{
		(*threads)[i] = CreateThread(NULL, 0, thread_dump, item_list, 0, NULL);

		if ((*threads)[i] == NULL)
		{
			ret |= PE_STATUS_COULD_NOT_CREATE_THREAD;
			break;
		}
	}

	--i;

	if (ret != PE_STATUS_SUCCESS)
	{
		for (signed int j = i; j >= 0; --j)
		{
			TerminateThread(*threads[i], PE_STATUS_COULD_NOT_CREATE_THREAD);
		}
	}

	return ret;
}

int main(int argc, char* argv[])
{
	PE_STATUS status = PE_STATUS_SUCCESS;

#ifdef PE_DEBUG
	long begin = clock();
#endif

	BYTE no_threads = 8;

	HANDLE* threads = NULL;
	HANDLE scan_file = NULL;

	PLIST_ENTRY item_list = (LIST_ENTRY *)malloc(sizeof(LIST_ENTRY));
	InitializeListHead(item_list);
	
	if (argc < 2 && argc > 4)
	{
		status = PE_STATUS_WRONG_ARGUMENT_COUNT;
		goto cleanup;
	}

	InitializeCriticalSectionAndSpinCount(&critical_section, 1000);
	th_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	finished = FALSE;
	found_file = FALSE;

	TCHAR log_file[MAX_PATH] = { 0 };
	TCHAR current_directory[MAX_PATH] = { 0 };
	TCHAR file_name[MAX_PATH] = { 0 };

	GetCurrentDirectory(MAX_PATH, log_file);

	PE_CHECK(path_append(log_file, MAX_PATH, "logs"));

	PE_CHECK(path_append(log_file, MAX_PATH, "scan.results"));

	scan_file = CreateFile(
		log_file,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (scan_file == INVALID_HANDLE_VALUE)
	{
		status = PE_STATUS_COULD_NOT_CREATE_FILE;
		goto cleanup;
	}

	PE_CHECK(get_directory_name(current_directory, argv[1]));

	PE_CHECK(get_file_name(file_name, argv[1]));

	BOOL rec = FALSE;

	if (argc == 2)
	{
		PE_CHECK(initialize_threads(&threads, no_threads, item_list));

		scan_current_directory_files(file_name, current_directory, rec, no_threads, item_list, threads, scan_file);
	}
	else
	{
		if (strcmp(argv[2], "r") == 0)
		{
			rec = TRUE;
		}

		if (argc == 3)
		{
			if (rec)
			{
				PE_CHECK(initialize_threads(&threads, no_threads, item_list));

				scan_current_directory_files(file_name, current_directory, rec, no_threads, item_list, threads, scan_file);
			}
			else
			{
				char *tmp;
				no_threads = (BYTE)strtol(argv[2], &tmp, 10);

				if (*tmp != '\0' || no_threads == 0)
				{
					status = PE_STATUS_INVALID_THREAD_COUNT;
					goto cleanup;
				}

				PE_CHECK(initialize_threads(&threads, no_threads, item_list));

				scan_current_directory_files(file_name, current_directory, rec, no_threads, item_list, threads, scan_file);
			}
		}
		else
		{
			char *tmp;
			no_threads = (BYTE)strtol(argv[3], &tmp, 10);

			if (*tmp != '\0' || no_threads == 0)
			{
				status = PE_STATUS_INVALID_THREAD_COUNT;
				goto cleanup;
			}

			PE_CHECK(initialize_threads(&threads, no_threads, item_list));

			scan_current_directory_files(file_name, current_directory, rec, no_threads, item_list, threads, scan_file);
		}
	}

	finished = TRUE;
	SetEvent(&th_event);

	DWORD th_wait = 0;
	if (found_file)
	{
		for (DWORD i = 0; i < no_threads; ++i)
		{
			th_wait = WaitForSingleObject(threads[i], INFINITE);

			if (th_wait & WAIT_FAILED)
			{
				printf("BAI MARE\n");
				exit(PE_STATUS_THREAD_WAIT_ERROR);
			}
		}
	}
	else
	{
		for (DWORD i = 0; i < no_threads; ++i)
		{
			TerminateThread(threads[i], 0);
		}
	}

	free(threads);

cleanup:
	if (!(status & PE_STATUS_COULD_NOT_CREATE_FILE))
	{
		CloseHandle(scan_file);
	}

	if (status & PE_STATUS_WRONG_ARGUMENT_COUNT)
	{
		printf("Invalid number of arguments.\n%s <argument 1> [r] [number_of_threads]\n", argv[0]);
	}

	if (status & PE_STATUS_INVALID_PATH_ARGUMENT)
	{
		printf("Invalid path argument.\n");
	}

	if (status & PE_STATUS_INVALID_THREAD_COUNT)
	{
		printf("Invalid thread count.\n");
	}

	if (status & PE_STATUS_PATH_OUT_OF_RANGE)
	{
		printf("Path out of range (max 256 characters).\n");
	}

	if (status & PE_STATUS_COULD_NOT_CREATE_THREAD)
	{
		printf("Could not create thread(s).\n");
	}

	free(item_list);
	DeleteCriticalSection(&critical_section);

#ifdef PE_DEBUG
	_CrtDumpMemoryLeaks();
	long end = clock();
	double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("Time spent : %f\n", time_spent);
	printf("Return code: %#x\n", status);
#endif

	return status;
}