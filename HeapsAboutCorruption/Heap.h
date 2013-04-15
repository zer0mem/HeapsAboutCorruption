/**
 * @file Heap.h
 * @author created by: Peter Hlavaty
 * @author created on: 2012/04/10
 */

#ifndef __HEAP_H__
#define __HEAP_H__

#include "sal.h"
#include "Windows.h"

#include "common.h"

#define CHECK_ALLOC_RET(chunk, n) {chunk = Alloc(n); if (NULL == chunk) return; }
#define CHECK_ALLOC_RETN(chunk, n) {chunk = Alloc(n); if (NULL == chunk) return NULL; }
#define CHECK_ALLOC_RETB(chunk, n) {chunk = Alloc(n); if (NULL == chunk) { printf("\r\n!alloc fail!\r\n"); return false; } }
#define CHECK_ALLOC_COALESCING_RETB(chunk, n) {chunk = Alloc(n); if (NULL == chunk) return false; if (NULL == Alloc(n)) return false;}


#pragma pack(push, 1)

#ifdef WIN8

struct RTL_BITMAP_EX
{
	size_t SizeOfBitMap;
	BYTE* Buffer;
};

struct HEAP_USERDATA_HEADER
{
	void* SubSegment;
	void* Reserved;
	ULONG SizeIndexAndPadding;
	ULONG Signature;
	WORD FirstAllocationOffset;
	WORD BlockStride;
	BYTE ReservedB[4];
	RTL_BITMAP_EX BusyBitmap;
	ULONG_PTR BitmapData;
};

#else

struct HEAP_USERDATA_HEADER
{
	void* SubSegment;
	void* Reserved;
	ULONG SizeIndexAndPadding;
	ULONG Signature;
};

#endif

#if defined(WIN7) || defined(WIN8)

struct HEAP_ENTRY
{

#ifdef WIN64

	union
	{
		ULONG_PTR PreviousBlockPrivateData;
		ULONG_PTR ReservedForAlignment;
		ULONG_PTR Reserved;
	};

#endif

	union
	{
		struct
		{
			union
			{
				struct  
				{
					USHORT Size;
					BYTE Flags;
					BYTE SmallTagIndex;
				};

				struct  
				{
					USHORT FunctionIndex;
					USHORT ContextValue;
				};

				ULONG Code1;
				ULONG InterceptorValue;
			};

			union
			{
				USHORT PreviousSize;
				USHORT UnusedBytesLength;
				USHORT Code2;
			};

			union 
			{
				BYTE SegmentOffset;
				BYTE LFHFlags;
				BYTE EntryOffset;

				BYTE Code3;
			};

			union
			{
				BYTE ExtendedBlockSignature;
				BYTE Code4;
			};
		};

		ULONG_PTR SubSegmentCode;
		ULONGLONG CompactHeader;
		ULONGLONG AgregateCode;

#ifndef WIN64
		ULONG_PTR Reserved;
#endif
	};

	LIST_ENTRY Links;
};

#else //winxp

struct HEAP_ENTRY
{
	SHORT Size;
	SHORT PrevSize;
	BYTE Cookie;
	BYTE Flags;
	BYTE UnusedBytes;
	BYTE SegmentIndex;
	LIST_ENTRY Links;
};

#endif

#pragma pack(pop)

class CHeap
{
	#define FREELIST0_DELTA		0x7F

public:
	CHeap() : m_heap(HeapCreate(0,0,0))
	{
		memset(&m_lfh, NULL, sizeof(m_lfh));
	}

	~CHeap()
	{
		//deallocate all LFH enabled chunks
		for (int n = 0; n < 0x80; n++)
			for (int i = 0; i < 0x12; i++)
				if (NULL != m_lfh[n][i])
					HeapFree(m_heap, 0, m_lfh[n][i]);
		
		HeapDestroy(m_heap);
	}

	void* Alloc(__in size_t n)
	{
		return HeapAlloc(m_heap, 0, n * HEAP_MIN_PAGE_SIZE);
	}

	void Free(__in void* block)
	{
		if (NULL != block)
			HeapFree(m_heap, 0, block);
	}

	__checkReturn bool ActivateHeapCache()
	{
		for (int i = 0; i < 0x100; i++)
		{
			void* block;
			CHECK_ALLOC_RETB(block, 0x10000 / HEAP_MIN_PAGE_SIZE);
			Free(block);
		}

		return true;
	}

	__checkReturn bool ActivateLFH(__in size_t n)
	{
		if (n >= 0x80)
			return false;

		//already activated
		if (NULL != m_lfh[n][0])
			return false;

		for (int i = 0; i < 0x12; i++)
			CHECK_ALLOC_RETB(m_lfh[n][i], n);

		return true;
	};

	//customized, realworld simulation of heapspray is little time consuming ;)
	__checkReturn bool HeapSpray(__in size_t n, __in size_t sz, __in_bcount(sz) const void* buff, __in_opt ULONG_PTR addr = NULL)
	{
		void* block = NULL;
		for (int i = 0; i < 0x10000; i++)
		{
			CHECK_ALLOC_RETB(block, n);

			if (NULL == addr)
			{
				RtlFillMemoryWithBuffer(block, n, buff, sz);
			}
			else if ((ULONG_PTR)block <= addr && (ULONG_PTR)block + n * HEAP_MIN_PAGE_SIZE >= addr + sz)
			{
				//optimalization .. dont wait for regular heapspray in test cases!!

				//RtlFillMemoryWithBuffer(block, n, buff, sz);
				RtlFillMemoryWithBuffer((void*)addr, ((ULONG_PTR)block + n * HEAP_MIN_PAGE_SIZE - addr) / sz, buff, sz);
				return true;
			}
		}
		

		printf("\n!heap spray failed!\n");
		return false;
	}

protected:
	virtual void EmptyLookAside(__in short n) = NULL;
	virtual void FillLookAside(__in short n) = NULL;

	HEAP_ENTRY* GetChunk(__in const void* data)
	{
		return (HEAP_ENTRY*)((ULONG_PTR)data - offsetof(HEAP_ENTRY, Links));
	}

	void EmptyAviableFreeChunks(__in short n)
	{
		//empty chunk >= ln from freelist
		for (int i = 0; i < 0x10; i++)
			Alloc(n);
	}

	__checkReturn bool PopulateFreeList(__in short n, __in int count = 1)
	{
		if (count < 1 || count > 0x100)
			return false;

		//freelist[0]
		short delta = (n < 0x80) ? 0 : FREELIST0_DELTA;

		void* blocks[0x100];
		RtlZeroMemory(blocks, sizeof(blocks));

		for (int i = 0; i < count; i++)
			CHECK_ALLOC_COALESCING_RETB(blocks[i], n + i * delta);

		FillLookAside(n);

		for (int i = count; i >= 0; i--)
			Free(blocks[i]); //insert chunk to freelist!

		EmptyLookAside(n);
		return true;
	}

protected:
	HANDLE m_heap;

	void* m_lfh[0x80][0x12];
};

#endif //__HEAP_H__
