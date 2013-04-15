/**
 * @file AutoMalloc.h
 * @author created by: Peter Hlavaty
 * @author created on: 2012/06/05
 */

#ifndef __AUTOMALLOC_H__
#define __AUTOMALLOC_H__

class CAutoMalloc
{
public:
	CAutoMalloc(__in size_t size)
	{
		m_size = 0;
		m_mem = malloc(size);
		if (m_mem)
			m_size = size;
	}

	~CAutoMalloc()
	{
		if (m_mem)
			free(m_mem);
	}

	__checkReturn void* GetMemory()
	{
		return m_mem;
	}

protected:
	void* m_mem;
	size_t m_size;
};

#endif //__AUTOMALLOC_H__
