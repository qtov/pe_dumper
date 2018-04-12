#include "main.h"
#include "dump.h"
#include "utils.h"

int main(int argc, char* argv[])
{
	PE_STATUS ret = PE_STATUS_SUCCESS;
	PE_STATUS status;

	if (argc != 2 && argc != 3)
	{
		printf("Invalid number of arguments.\n%s <argument 1> [<argument 2>]\n", argv[0]);
		return PE_STATUS_WRONG_ARGUMENT_COUNT;
	}

	TCHAR current_directory[4096] = { 0 };
	TCHAR file_name[4096] = { 0 };

	//GetCurrentDirectory(
	//	4096,
	//	current_directory
	//);

	if ((status = get_directory_name(current_directory, argv[1])) != PE_STATUS_SUCCESS)
	{
		goto cleanup;
	}

	if ((status = get_file_name(file_name, argv[1])) != PE_STATUS_SUCCESS)
	{
		goto cleanup;
	}

	if ((status = validate_path(argv[1])) != PE_STATUS_SUCCESS)
	{
		goto cleanup;
	}

	if (argc == 2)
	{
		dump_current_directory_files(file_name, current_directory, FALSE);
	}
	else
	{
		dump_current_directory_files(file_name, current_directory, TRUE);
	}

cleanup:
	if (status & PE_STATUS_INVALID_PATH_ARGUMENT)
	{
		printf("Invalid path argument.\n");
	}
	
	return ret;
}