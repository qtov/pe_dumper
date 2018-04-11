#include "utils.h"

BOOL in_arr(WORD item, WORD arr[])
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