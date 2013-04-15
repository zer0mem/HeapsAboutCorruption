/**
 * @file vtable.h
 * @author created by: Peter Hlavaty
 * @author created on: 2012/04/10
 */

#ifndef __VTABLE_H__
#define __VTABLE_H__

#define VTABLE(ref_obj)	(void*)(*(ULONG_PTR*)(ref_obj))

class CVTable
{
public:
	virtual void NoSafeHeap() = 0;
};

class CTarget : CVTable
{
public:
	void NoSafeHeap()
	{
		printf("safe!");
	}
};

class CRuleTheWorld : CVTable
{
public:
	void NoSafeHeap()
	{
		printf("\r\n\r\n\t\t~~~::*Heap owned*!!~~~\r\n\r\n");
	}
};

template <class HEAP>
class CAutoVtableRewrite
{
public:
	template <class HEAP>
	//__in int offset is here just because of this is just PoC
	//and project is just demonstration...
	CAutoVtableRewrite(__in size_t n, __in HEAP& heap, __in bool pointer = false, __in int offset = 0)
	{
		m_alloc = (ULONG_PTR*)((ULONG_PTR)heap.Alloc(n) + offset);
		m_vtable = *m_alloc;

		CDebug::DbgPrint("\n vtable : %x ", (ULONG_PTR)m_alloc);

		if (!pointer)
			*m_alloc = (ULONG_PTR)VTABLE(&m_rule);
		else
			*m_alloc = *(ULONG_PTR*)VTABLE(&m_rule);
	}

	~CAutoVtableRewrite()
	{
		*m_alloc = m_vtable;
	}

private:
	ULONG_PTR* m_alloc;
	ULONG_PTR m_vtable;

	CRuleTheWorld m_rule;
};

#endif //__VTABLE_H__
