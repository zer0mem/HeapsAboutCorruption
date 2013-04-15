/**
 * @file debug.h
 * @author created by: Peter Hlavaty
 * @author created on: 2012/11/12
 */

#ifndef __DEBUG_H__
#define __DEBUG_H__

#ifdef _WIN64
EXTERN_C void __kebreak();
#define INT13 {}//__kebreak()
#else
#define INT13 { __asm int 3 }
#endif

#ifdef WIN64
EXTERN_C ULONG __timestamp();
#define RDTSC __timestamp()
#else
#define RDTSC { __asm rdtsc }
#endif

class CDebug
{
public:
	static void DbgPrint(__in const char* msg, __in ULONG_PTR a = 0, __in ULONG_PTR b = 0, __in ULONG_PTR c = 0, __in ULONG_PTR d = 0, __in ULONG_PTR e = 0)
	{
		RtlZeroMemory(m_output, sizeof(m_output));
		sprintf_s(m_output, msg, a, b, c, d, e);
		OutputDebugStringA(m_output);
		printf(m_output);
	}

	static void KeBreak()
	{
		INT13;
	}

	static void WaitForDbg()
	{
		printf("\ntime to get inside dbg!! {press some key + enter}\n");
		getchar();
		DbgPrint("\nDebugger entered!\n");
	}

private:
	static CHAR m_output[0x100];
};

CHAR CDebug::m_output[0x100];

#endif //__DEBUG_H__
