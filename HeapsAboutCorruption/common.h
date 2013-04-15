/**
 * @file common.h
 * @author created by: Peter Hlavaty
 * @author created on: 2012/04/10
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>
#include "conio.h"

#include <time.h>

#include "Heap.h"


#define HEAP_MIN_PAGE_SIZE		(2 * sizeof(ULONG_PTR))//sizeof(HEAP_ENTRY)
#define SPRAY_ADDR				0x23404400//0x04000000
#define HEAP_CASH_ENTRY_N		0x397
#define HEAP_FREELIST_WIN7X86_N	(0x123 + 0x30)//(0x183 + 0x30)

#define IS_ALIGNED(sz, val)	(0 == sz % sizeof(val))

template <class TYPE>
void RtlFillMemoryTypeVal(__in void* buffer, __in size_t count, __in const TYPE& val)
{
	for (size_t i = 0; i < count; i++)
		*((TYPE*)buffer + i) = val;
}

void RtlFillMemoryWithBuffer(__inout_bcount(n) void* dest, __in size_t n, __in_bcount(sz) const void* buffer, __in size_t sz)
{
	for (size_t j = 0; j < n; j++)
		memcpy((byte*)dest + (j * sz), buffer, sz);
}

#endif //__COMMON_H__
