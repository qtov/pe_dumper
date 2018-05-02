#pragma once

#define PE_CHECK(fct) \
if ((status |= (fct))!= PE_STATUS_SUCCESS) { goto cleanup; }

#define THREAD_ITEM_CONVERT(l) (THREAD_ITEM *)(((BYTE *)(l)) - sizeof(THREAD_ITEM) + sizeof(LIST_ENTRY))
