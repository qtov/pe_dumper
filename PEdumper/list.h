#pragma once

#include <Windows.h>

VOID
InitializeListHead(
	__out PLIST_ENTRY ListHead
);

__checkReturn
BOOLEAN
FORCEINLINE
IsListEmpty(
	__in const LIST_ENTRY * ListHead
);

FORCEINLINE
BOOLEAN
RemoveEntryList(
	__in PLIST_ENTRY Entry
);

FORCEINLINE
PLIST_ENTRY
RemoveHeadList(
	__inout PLIST_ENTRY ListHead
);

FORCEINLINE
PLIST_ENTRY
RemoveTailList(
	__inout PLIST_ENTRY ListHead
);

FORCEINLINE
VOID
InsertTailList(
	__inout PLIST_ENTRY ListHead,
	__inout __drv_aliasesMem PLIST_ENTRY Entry
);

FORCEINLINE
VOID
InsertHeadList(
	__inout PLIST_ENTRY ListHead,
	__inout __drv_aliasesMem PLIST_ENTRY Entry
);

BOOLEAN
InterlockedIsListEmpty(
	__in const LIST_ENTRY* ListHead,
	__in CRITICAL_SECTION* ListLock
);

PLIST_ENTRY
InterlockedRemoveHeadList(
	__inout PLIST_ENTRY ListHead,
	__in CRITICAL_SECTION* ListLock
);

BOOLEAN
InterlockedRemoveEntryList(
	__in PLIST_ENTRY Entry,
	__in CRITICAL_SECTION* ListLock
);

VOID
InterlockedInsertTailList(
	__inout PLIST_ENTRY ListHead,
	__inout __drv_aliasesMem PLIST_ENTRY Entry,
	__in CRITICAL_SECTION* ListLock
);