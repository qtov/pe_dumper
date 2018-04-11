#include "main.h"
#include "dump.h"

int main(int argc, char* argv[])
{
	if (argc != 2 && argc != 3)
	{
		printf("Invalid number of arguments.\n%s <argument 1> [<argument 2>]\n", argv[0]);
		exit(1);
	}

	TCHAR current_directory[4096];

	GetCurrentDirectory(
		4096,
		current_directory
	);

	if (argc == 2)
	{
		dump_current_directory_files(argv[1], current_directory, FALSE);
	}
	else
	{
		dump_current_directory_files(argv[1], current_directory, TRUE);
	}

	return 0;
}