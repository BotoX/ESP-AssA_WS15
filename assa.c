//-----------------------------------------------------------------------------
// assa.c
//
// Brainfuck interpreter
//
//-----------------------------------------------------------------------------
//

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#define ERROR(error, fmt, ...) \
	do { \
		fprintf(/*stderr*/stdout, "[ERR] " fmt, ##__VA_ARGS__); \
		exit(error); \
	} while(0)

// Uncomment for bonus
//#define BONUS
#ifdef BONUS
	#include <sys/mman.h>
	#include <unistd.h>
	#define MEMPAGESIZE sysconf(_SC_PAGE_SIZE)
	#define MEMPAGEMASK ~(MEMPAGESIZE - 1)

	#include <signal.h>
	// 3hard5me, this runs in kernel context, can't access registers in brainfuck machinecode
	// need to switch context into old execution path - too much work
	static void SIGSEGV_Handler(int Signal, siginfo_t *pSignal, void *pArg)
	{
		unsigned char *pData;
		// mov  [ebp+pData], edx ; Get data pointer
		// ^ intel syntax
		// v gas syntax
		asm("mov %%edx, %[pData]"
				: [pData] "=r" (pData) :: "edx");

		// Hack to avoid global vars
		static unsigned char **ppDataStart = 0;
		static size_t *pDataAllocSize = 0;
		if(Signal != SIGSEGV)
		{
			ppDataStart = (unsigned char **)pSignal;
			pDataAllocSize =  (size_t *)pArg;
			return;
		}

		printf("pData: %p\n", pData);
		size_t DataOffset = pData - *ppDataStart;

		ucontext_t *pContext = pArg;
		printf("Got SIGSEGV at address: 0x%lx | DataOffset: %u\n", (long)pSignal->si_addr, DataOffset);

		exit(1);

		mprotect(*ppDataStart, *pDataAllocSize + MEMPAGESIZE, PROT_READ | PROT_WRITE);
		*pDataAllocSize += MEMPAGESIZE;
		void *pAlloc = mremap(*ppDataStart, *pDataAllocSize, *pDataAllocSize + MEMPAGESIZE, MREMAP_MAYMOVE);
		if(pAlloc == MAP_FAILED) // this could be anything, need to check errno...
			ERROR(2, "out of memory\n");

		*ppDataStart = pAlloc;

		pData = *ppDataStart + DataOffset;
		// mov  edx, [ebp+pData] ; Fix data pointer
		// ^ intel syntax
		// v gas syntax
		asm("mov %[pData], %%edx"
				:: [pData] "m" (pData) : "edx");
	}
#endif


/* CStack */
typedef struct
{
	size_t *pData;
	size_t Size;
	size_t AllocSize;
} CStack;

void Stack_Alloc(CStack *pStack, size_t Size)
{
	if(pStack->AllocSize == 0)
	{
		pStack->AllocSize = Size;
		pStack->pData = malloc(pStack->AllocSize * sizeof(size_t));
		if(!pStack->pData)
			ERROR(2, "out of memory\n");
	}
	else
	{
		pStack->AllocSize += Size;
		void *pAlloc = realloc(pStack->pData, pStack->AllocSize * sizeof(size_t));
		if(!pStack->pData)
		{
			free(pStack->pData);
			ERROR(2, "out of memory\n");
		}
		pStack->pData = pAlloc;
	}
}

void Stack_Init(CStack *pStack, size_t StartSize)
{
	pStack->Size = 0;
	pStack->AllocSize = 0;
	if(StartSize)
		Stack_Alloc(pStack, StartSize);
}

void Stack_Destroy(CStack *pStack)
{
	pStack->Size = 0;
	pStack->AllocSize = 0;
	free(pStack->pData);
}

uint32_t Stack_Top(CStack *pStack)
{
	if(pStack->Size == 0)
		return UINT32_MAX;

	return pStack->pData[pStack->Size - 1];
}

uint32_t Stack_Push(CStack *pStack, uint32_t Element)
{
	if(pStack->Size >= pStack->AllocSize)
		Stack_Alloc(pStack, 32);

	pStack->pData[pStack->Size++] = Element;
	return Element;
}

uint32_t Stack_Pop(CStack *pStack)
{
	if(pStack->Size == 0)
		return UINT32_MAX;

	return pStack->pData[--pStack->Size];
}
/* CStack */


size_t LoadProgram(const char *pFilename, char **ppProgram)
{
	char *pFileData;
	FILE *pFile;
	pFile = fopen(pFilename, "rb");
	if(!pFile)
		ERROR(4, "reading the file failed\n");

	size_t FileSize;
	fseek(pFile, 0, SEEK_END);
	FileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	pFileData = malloc(FileSize + 1);
	if(!pFileData)
		ERROR(2, "out of memory\n");

	fread(pFileData, 1, FileSize, pFile),
	fclose(pFile);

	// Assure null-termination
	pFileData[FileSize] = 0;

	// Count valid brainfuck characters
	size_t RealLength = 0;
	size_t i;
	for(i = 0; i < FileSize; i++)
	{
		switch(pFileData[i])
		{
			case '>':
			case '<':
			case '+':
			case '-':
			case '.':
			case ',':
			case '[':
			case ']':
			{
				RealLength++;
			} break;
		}
	}

	// Allocate memory for the filtered code
	char *pProgram = malloc(RealLength + 1);
	if(!pProgram)
		ERROR(2, "out of memory\n");

	// And copy only the valid characters
	size_t j;
	for(i = 0, j = 0; i < FileSize; i++)
	{
		switch(pFileData[i])
		{
			case '>':
			case '<':
			case '+':
			case '-':
			case '.':
			case ',':
			case '[':
			case ']':
			{
				pProgram[j++] = pFileData[i];
			} break;
		}
	}

	// Assure null-termination
	pProgram[RealLength] = 0;

	free(pFileData);

	*ppProgram = pProgram;

	return RealLength;
}

// O(1) '[...]' implementation
// This would be a lot more memory efficient by using something like a Y-fast trie
// https://en.wikipedia.org/wiki/Y-fast_trie
// (which'd be wayyyy too much effort for me to implement for this assignment)
// or this great library: http://www.nedprod.com/programs/portable/nedtries/
// in case of hanoi.bf it'll use about 218k memory
int BuildJumpTable(char *pBuf, size_t Length, uint32_t **ppJumpTable)
{
	CStack Stack;
	CStack *pStack = &Stack;
	Stack_Init(pStack, 32);

	size_t OpenBracketSize = 0;
	size_t ClosedBracketSize = 0;
	size_t LastBracket = 0;

	// Count '[' and ']' in the program
	// Also remember the last ']' to make memory usage a bit better
	size_t i;
	for(i = 0; i < Length; i++)
	{
		switch(pBuf[i])
		{
			case '[':
			{
				OpenBracketSize++;
			} break;
			case ']':
			{
				ClosedBracketSize++;
				LastBracket = i;
			} break;
		}
	}
	LastBracket++;

	if(OpenBracketSize != ClosedBracketSize)
		ERROR(3, "parsing of input failed\n");

	uint32_t *pJumpTable = malloc(LastBracket * sizeof(uint32_t));
	if(!pJumpTable)
		ERROR(2, "out of memory\n");

	memset(pJumpTable, 0, LastBracket * sizeof(uint32_t));

	for(i = 0; i < Length; i++)
	{
		switch(pBuf[i])
		{
			case '[':
			{
				// Push position of '[' onto stack
				// This will be pop'd later at the corresponding ']'
				Stack_Push(pStack, i);
			} break;
			case ']':
			{
				uint32_t Jump = Stack_Pop(pStack);

				pJumpTable[i] = Jump;
				pJumpTable[Jump] = i;
			} break;
		}
	}

	Stack_Destroy(pStack);

	*ppJumpTable = pJumpTable;

	return 0;
}

typedef struct
{
	uint32_t Position;
	char *pProgram;
	size_t ProgramSize;

	uint32_t *pJumpTable;

	uint32_t *pBreakPoints;
	size_t BreakPointSize;
	char *pBreakPointBackups;

	unsigned char *pDataStart;
	unsigned char *pData;

	size_t DataSize;
	size_t DataAllocSize;
} CBrainfuckContext;

void BrainfuckContext_Init(CBrainfuckContext *pContext, char *pProgram, uint32_t *pJumpTable)
{
	memset(pContext, 0, sizeof(CBrainfuckContext));
	pContext->DataAllocSize = 1024;
	pContext->pProgram = pProgram;
	pContext->pJumpTable = pJumpTable;
	pContext->pBreakPoints = 0;
	pContext->BreakPointSize = 0;
	pContext->pBreakPointBackups = 0;

	pContext->pDataStart = malloc(pContext->DataAllocSize);
	pContext->DataSize = pContext->DataAllocSize;
	pContext->pData = pContext->pDataStart;
	memset(pContext->pData, 0, pContext->DataSize);

	if(!pContext->pData)
		ERROR(2, "out of memory\n");
}

uint32_t RunBrainfuck(CBrainfuckContext *pContext)
{
	// gcc can't into optimizing >_>
	register uint32_t Position = pContext->Position;
	register const char *pProgram = pContext->pProgram;
	unsigned char *pDataStart = pContext->pDataStart;
	register unsigned char *pData = pContext->pData;
	unsigned char *pDataEnd = pDataStart + pContext->DataSize;
	register uint32_t *pJumpTable = pContext->pJumpTable;

	for(;; Position++)
	{
		switch(pProgram[Position])
		{
			case '>':
			{
				pData++;

				// Boundary overflow check
				if(pData >= pDataEnd)
				{
					pContext->DataSize += pContext->DataAllocSize;
					void *pAlloc = realloc(pDataStart, pContext->DataSize);
					if(!pAlloc)
						ERROR(2, "out of memory\n");

					pData = pAlloc + (pData - pDataStart);
					pDataStart = pAlloc;
					pDataEnd = pDataStart + pContext->DataSize;
					memset(pData, 0, pDataEnd - pData);
				}
			} break;
			case '<':
			{
				pData--;
				// Underflow not documented, therefore not implemented
			} break;
			case '+':
			{
				(*pData)++;
			} break;
			case '-':
			{
				(*pData)--;
			} break;
			case '.':
			{
				putchar(*pData);
			} break;
			case ',':
			{
				*pData = (unsigned char)(getchar() & 0xFF);
			} break;
			case '[':
			{
				if(!*pData)
					Position = pJumpTable[Position];
			} break;
			case ']':
			{
				if(*pData)
					Position = pJumpTable[Position];
			} break;
			default:
			{
				pContext->Position = Position;
				pContext->pDataStart = pDataStart;
				pContext->pData = pData;

				return Position;
			} break;
		}
	}
}

/* Console */
typedef int (*pfnCommand)(CBrainfuckContext *pContext, int argc, char *argv[]);
typedef struct
{
	const char *pCmd;
	pfnCommand pfnCmd;
} CCommand;

int CMD_load(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("[ERR] wrong parameter count\n");
		return 1;
	}

	if(pContext->pProgram)
	{
		free(pContext->pProgram);
		pContext->pProgram = 0;

		if(pContext->pJumpTable)
		{
			free(pContext->pJumpTable);
			pContext->pJumpTable = 0;
		}

		if(pContext->pBreakPoints)
		{
			free(pContext->pBreakPoints);
			pContext->pBreakPoints = 0;

			if(pContext->pBreakPointBackups)
			{
				free(pContext->pBreakPointBackups);
				pContext->pBreakPointBackups = 0;
			}
		}
	}

	pContext->ProgramSize = LoadProgram(argv[1], &pContext->pProgram);
	BuildJumpTable(pContext->pProgram, pContext->ProgramSize, &pContext->pJumpTable);

	return 0;
}

int CMD_run(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(!pContext->pProgram)
	{
		printf("[ERR] no program loaded\n");
		return 1;
	}

	// Already ran once, cleanup first
	// If pBreakPointBackups is set then we've previously stopped at a breakpoint ...
	// ... which means that we *don't* want to reset data when re-'run'ing
	if(pContext->Position && !pContext->pBreakPointBackups)
	{
		pContext->Position = 0;
		memset(pContext->pDataStart, 0, pContext->DataSize);
		pContext->pData = pContext->pDataStart;
	}

	if(pContext->pBreakPoints)
	{
		size_t i;
		if(!pContext->pBreakPointBackups)
		{
			// Create array for storing original instructions
			pContext->pBreakPointBackups = malloc(pContext->BreakPointSize);
			if(!pContext->pBreakPointBackups)
				ERROR(2, "out of memory\n");

			for(i = 0; i < pContext->BreakPointSize; i++)
			{
				// Ignore breakpoints which have already been passed
				if(!pContext->pBreakPoints[i])
					continue;

				// Position of breakpoint in pProgram
				uint32_t Position = pContext->pBreakPoints[i];

				// Save original instruction ...
				pContext->pBreakPointBackups[i] = pContext->pProgram[Position];
				// ... and overwrite with 0, causing RunBrainfuck to return at <Position>
				pContext->pProgram[Position] = 0;
			}
		}

		uint32_t ReturnCode = RunBrainfuck(pContext);

		// Program ended
		if(ReturnCode == pContext->ProgramSize)
		{
			// Restore original program (in case we didn't hit a breakpoint we've set)
			for(i = 0; i < pContext->BreakPointSize; i++)
			{
				if(!pContext->pBreakPoints[i])
					continue;

				uint32_t Position = pContext->pBreakPoints[i];

				pContext->pProgram[Position] = pContext->pBreakPointBackups[i];
			}

			// Don't need this anymore
			free(pContext->pBreakPoints);
			pContext->pBreakPoints = 0;

			free(pContext->pBreakPointBackups);
			pContext->pBreakPointBackups = 0;

			return 0;
		}

		// Stopped at breakpoint
		uint32_t BreakPoint = 0;
		for(i = 0; i < pContext->BreakPointSize; i++)
		{
			// Find the pBreakPoints array index which made our program return ...
			if(pContext->pBreakPoints[i] == ReturnCode)
			{
				BreakPoint = i;
				break;
			}
		}

		// ... and restore the original instruction
		pContext->pProgram[ReturnCode] = pContext->pBreakPointBackups[BreakPoint];
		// Delete breakpoint so we don't use it again
		pContext->pBreakPoints[BreakPoint] = 0;
	}
	else
		RunBrainfuck(pContext);

	return 0;
}

int CMD_eval(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("[ERR] wrong parameter count\n");
		return 1;
	}

	// Store original context
	CBrainfuckContext OldContext;
	memcpy(&OldContext, pContext, sizeof(CBrainfuckContext));

	// load new program
	pContext->pProgram = argv[1];
	pContext->ProgramSize = strlen(argv[1]);
	pContext->Position = 0;
	pContext->pJumpTable = 0;

	BuildJumpTable(pContext->pProgram, pContext->ProgramSize, &pContext->pJumpTable);
	RunBrainfuck(pContext);

	// Clean up
	free(pContext->pJumpTable);

	// Keep data pointer position?
	OldContext.pData = pContext->pData;

	// This could've changed
	OldContext.DataSize = pContext->DataSize;

	// Restore original context
	memcpy(pContext, &OldContext, sizeof(CBrainfuckContext));

	return 0;
}

int uint32_t_compare(const void *pL, const void *pR)
{
	uint32_t L = *(uint32_t *)pL;
	uint32_t R = *(uint32_t *)pR;

	if(L < R)
		return -1;
	else if(L > R)
		return 1;
	else
		return 0;
}

int CMD_break(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(!pContext->pProgram)
	{
		printf("[ERR] no program loaded\n");
		return 1;
	}

	if(argc < 2)
	{
		printf("[ERR] wrong parameter count\n");
		return 1;
	}

	long int Temp = strtol(argv[1], 0, 10);
	if(Temp <= 0 || Temp > pContext->ProgramSize)
		return 1;

	uint32_t BreakPoint = Temp;
	if(!pContext->pBreakPoints)
	{
		pContext->BreakPointSize = 1;
		pContext->pBreakPoints = malloc(pContext->BreakPointSize * sizeof(uint32_t));
		if(!pContext->pBreakPoints)
			ERROR(2, "out of memory\n");
	}
	else
	{
		// Avoid duplicate breakpoints
		size_t i;
		for(i = 0; i < pContext->BreakPointSize; i++)
		{
			if(pContext->pBreakPoints[i] == BreakPoint)
				return 1;
		}

		if(pContext->pBreakPointBackups)
		{
			// Restore original program first
			for(i = 0; i < pContext->BreakPointSize; i++)
			{
				if(!pContext->pBreakPoints[i])
					continue;

				uint32_t Position = pContext->pBreakPoints[i];

				pContext->pProgram[Position] = pContext->pBreakPointBackups[i];
			}

			// reset pBreakPointBackups so CMD_run builds it again and etc.
			free(pContext->pBreakPointBackups);
			pContext->pBreakPointBackups = 0;
		}

		// Allocate memory for new breakpoint
		pContext->BreakPointSize += 1;
		void *pAlloc = realloc(pContext->pBreakPoints, pContext->BreakPointSize * sizeof(uint32_t));
		if(!pAlloc)
			ERROR(2, "out of memory\n");

		pContext->pBreakPoints = pAlloc;
	}

	pContext->pBreakPoints[pContext->BreakPointSize - 1] = BreakPoint;

	return 0;
}

int CMD_step(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(!pContext->pProgram)
	{
		printf("[ERR] no program loaded\n");
		return 1;
	}

	uint32_t Position = 1;
	if(argc >= 2)
	{
		long int Temp = strtol(argv[1], 0, 10);
		if(Temp <= 0)
			return 1;

		if(Temp >= pContext->ProgramSize)
			return CMD_run(pContext, 0, 0);

		Position = Temp;
	}

	// Save original instruction and ...
	char Backup = pContext->pProgram[Position];
	// ... set it to 0 so RunBrainfuck returns here
	pContext->pProgram[Position] = 0;

	int Ret = CMD_run(pContext, 0, 0);

	// And restore the original instruction
	pContext->pProgram[Position] = Backup;

	return Ret;
}

int CMD_memory(CBrainfuckContext *pContext, int argc, char *argv[])
{
	int Position = pContext->pData - pContext->pDataStart;
	enum ETypes
	{
		TYPE_HEX,
		TYPE_INT,
		TYPE_BIN,
		TYPE_CHAR
	} Type;
	Type = TYPE_HEX;

	if(argc >= 2)
	{
		char *pNext;
		int Temp = strtol(argv[1], &pNext, 10);

		// Not a numerical input, asume type (convenience)
		if(pNext == argv[1] || *pNext != 0)
		{
			if(!strcasecmp(argv[1], "hex"))
				Type = TYPE_HEX;
			else if(!strcasecmp(argv[1], "int"))
				Type = TYPE_INT;
			else if(!strcasecmp(argv[1], "bin"))
				Type = TYPE_BIN;
			else if(!strcasecmp(argv[1], "char"))
				Type = TYPE_CHAR;
		}
		else
		{
			if(Temp >= pContext->DataSize || Temp < 0)
				return 1;

			Position = Temp;
		}
	}

	if(argc >= 3)
	{
		if(!strcasecmp(argv[2], "hex"))
			Type = TYPE_HEX;
		else if(!strcasecmp(argv[2], "int"))
			Type = TYPE_INT;
		else if(!strcasecmp(argv[2], "bin"))
			Type = TYPE_BIN;
		else if(!strcasecmp(argv[2], "char"))
			Type = TYPE_CHAR;
	}

	unsigned char *pData = pContext->pDataStart + Position;
	switch(Type)
	{
		case TYPE_HEX:
		{
			printf("Hex at %d: %x\n", Position, *pData);
		} break;
		case TYPE_INT:
		{
			printf("Integer at %d: %d\n", Position, *pData);
		} break;
		case TYPE_BIN:
		{
			char aBuf[16];
			char *pBuf = aBuf;

			size_t i;
			for(i = 128; i > 0; i >>= 1)
				*(pBuf++) = ((*pData & i) == i) ? '1' : '0';
			pBuf = 0;

			printf("Binary at %d: %s\n", Position, aBuf);
		} break;
		case TYPE_CHAR:
		{
			printf("Char at %d: %c\n", Position, *pData);
		} break;
	}

	return 0;
}

int CMD_show(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(!pContext->pProgram)
	{
		printf("[ERR] no program loaded\n");
		return 1;
	}

	size_t Size = 10;
	if(argc >= 2)
	{
		long int Temp = strtol(argv[1], 0, 10);
		if(Temp <= 0)
			return 1;
		Size = Temp;
	}

	// User wants to see the full thing
	if(pContext->Position + Size >= pContext->ProgramSize)
	{
		printf("%s\n", &pContext->pProgram[pContext->Position]);
		return 0;
	}

	// Mark end of string by '\0'
	char Backup = pContext->pProgram[pContext->Position + Size];
	pContext->pProgram[pContext->Position + Size] = 0;

	printf("%s\n", &pContext->pProgram[pContext->Position]);

	// And restore...
	pContext->pProgram[pContext->Position + Size] = Backup;

	return 0;
}

int CMD_change(CBrainfuckContext *pContext, int argc, char *argv[])
{
	int Position = pContext->pData - pContext->pDataStart;
	unsigned char Value = 0x00;

	if(argc >= 2)
		Position = strtol(argv[1], 0, 10);

	if(argc >= 3)
		Value = strtol(argv[2], 0, 16);

	unsigned char *pData = pContext->pDataStart + Position;

	*pData = Value;

	return 0;
}

int CMD_quit(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(pContext->pProgram)
		free(pContext->pProgram);
	if(pContext->pDataStart)
		free(pContext->pDataStart);
	if(pContext->pJumpTable)
		free(pContext->pJumpTable);
	if(pContext->pBreakPoints)
		free(pContext->pBreakPoints);

	if(argc)
		printf("Bye.\n");
	exit(0);
}

int CommandLine(CBrainfuckContext *pContext, CCommand *pCommand, char *pLine)
{
	char *apArgv[16] = {0};
	int Argc = 0;
	char *pStr = pLine;
	char Found = 1;
	char InString = 0;

	while(*pStr)
	{
		if(*pStr == '"' && *(pStr - 1) != '\\')
		{
			*pStr = 0;
			InString ^= 1;
			if(InString)
			{
				pStr++;
				Found = 1;
			}
		}

		if((*pStr == ' ' || *pStr == '\t') && !InString)
		{
			*pStr = 0;
			Found = 1;
		}
		else if(Found)
		{
			if(Argc < sizeof(apArgv)/sizeof(*apArgv))
			{
				apArgv[Argc++] = pStr;
				Found = 0;
			}
			else // ignore additional parameters
				break;
		}
		pStr++;
	}

	if(Argc)
	{
		while(pCommand->pCmd)
		{
			if(!strcasecmp(apArgv[0], pCommand->pCmd))
				return pCommand->pfnCmd(pContext, Argc, apArgv);

			pCommand++;
		}
	}

	return -1;
}
/* Console */

#ifdef BONUS
unsigned char *JITCompileBrainfuck(char *pBuf, size_t Length, size_t *pProgramAllocSize)
{
	CStack Stack;
	CStack *pStack = &Stack;
	Stack_Init(pStack, 32);

	unsigned char aInstpDataInc[] = {
		// add  edx, 1
		0x81, 0xC2, 0x01, 0x00, 0x00, 0x00
	};
	unsigned char aInstpDataDec[] = {
		// sub  edx, 1
		0x81, 0xEA, 0x01, 0x00, 0x00, 0x00
	};
	unsigned char aInstDataAdd[] = {
		// add  BYTE PTR [edx], 1
		0x80, 0x02, 0x01
	};
	unsigned char aInstDataSub[] = {
		// sub  BYTE PTR [edx], 1
		0x80, 0x2A, 0x01
	};
	unsigned char aInstDataNull[] = {
		// mov  BYTE PTR [edx], 0
		0xC6, 0x02, 0x00
	};
	unsigned char aInstPrintData[] = {
		// pusha ; save all general registers on stack
		0x60,
		// mov  ecx, edx ; pointer to data
		0x89, 0xD1,
		// mov  edx, 1 ; message length
		0xBA, 0x01, 0x00, 0x00, 0x00,
		// mov  ebx, 1 ; file descriptor (stdout)
		0xBB, 0x01, 0x00, 0x00, 0x00,
		// mov  eax, 4 ; system call number (sys_write)
		0xB8, 0x04, 0x00, 0x00, 0x00,
		// int  0x80 ; syscall
		0xCD, 0x80,
		// popa ; restore all general registers from stack
		0x61
	};
	unsigned char aInstJump[] = {
		// jmp  <relative addr>
		0xE9, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char aInstCondJump[] = {
		// cmp  BYTE PTR [edx], 0
		0x80, 0x3A, 0x00,
		// jne
		0x0F, 0x85, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char aInstReturnNormal[] = {
		// mov  eax, 0 ; return with 0
		0xB8, 0x00, 0x00, 0x00, 0x00,
		// retn
		0xC3
	};

	size_t ProgramSize = 0;
	// Align to memory page
	size_t ProgramAllocSize = (Length + MEMPAGESIZE) & MEMPAGEMASK;

	unsigned char *pProgram = mmap(0, ProgramAllocSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(pProgram == MAP_FAILED)
		ERROR(2, "out of memory\n");

	// translate into x86 instructions and optimize
	size_t i;
	for(i = 0; i < Length; i++)
	{
		switch(pBuf[i])
		{
			case '>':
			{
				if(pBuf[i - 1] == '>')
					pProgram[ProgramSize - 4] += 1;
				else
				{
					memcpy(&pProgram[ProgramSize], aInstpDataInc, sizeof(aInstpDataInc));
					ProgramSize += sizeof(aInstpDataInc);
				}
			} break;
			case '<':
			{
				if(pBuf[i - 1] == '<')
					pProgram[ProgramSize - 4] += 1;
				else
				{
					memcpy(&pProgram[ProgramSize], aInstpDataDec, sizeof(aInstpDataDec));
					ProgramSize += sizeof(aInstpDataDec);
				}
			} break;
			case '+':
			{
				if(pBuf[i - 1] == '+')
					pProgram[ProgramSize - 1] += 1;
				else
				{
					memcpy(&pProgram[ProgramSize], aInstDataAdd, sizeof(aInstDataAdd));
					ProgramSize += sizeof(aInstDataAdd);
				}
			} break;
			case '-':
			{
				if(pBuf[i - 1] == '-')
					pProgram[ProgramSize - 1] += 1;
				else
				{
					memcpy(&pProgram[ProgramSize], aInstDataSub, sizeof(aInstDataSub));
					ProgramSize += sizeof(aInstDataSub);
				}
			} break;
			case '.':
			{
				memcpy(&pProgram[ProgramSize], aInstPrintData, sizeof(aInstPrintData));
				ProgramSize += sizeof(aInstPrintData);
			} break;
			case ',':
			{
				// not implemented - who uses this anyways
			} break;
			case '[':
			{
				if(pBuf[i + 1] == '-' && pBuf[i + 2] == ']')
				{
					memcpy(&pProgram[ProgramSize], aInstDataNull, sizeof(aInstDataNull));
					ProgramSize += sizeof(aInstDataNull);
					i += 2;
				}
				else
				{
					memcpy(&pProgram[ProgramSize], aInstJump, sizeof(aInstJump));
					ProgramSize += sizeof(aInstJump);

					// relative jump to the next instruction
					Stack_Push(pStack, ProgramSize);
				}
			} break;
			case ']':
			{
				size_t Jump = Stack_Pop(pStack);
				if(Jump == SIZE_MAX)
					ERROR(3, "parsing of input failed\n");

				memcpy(&pProgram[ProgramSize], aInstCondJump, sizeof(aInstCondJump));

				uint32_t RelativeJmpAddr;

				// jump to ']' from '['
				RelativeJmpAddr = ProgramSize - Jump;
				memcpy(&pProgram[Jump - 4], &RelativeJmpAddr, 4);

				ProgramSize += sizeof(aInstCondJump);

				// conditional jump back to '[' from ']'
				RelativeJmpAddr = ProgramSize - Jump;
				RelativeJmpAddr *= -1;
				memcpy(&pProgram[ProgramSize - 4], &RelativeJmpAddr, 4);

			} break;
		}

		if(ProgramAllocSize - ProgramSize <= sizeof(aInstPrintData))
		{
			// This works because our jumps are relative
			ProgramAllocSize += MEMPAGESIZE;
			void *pAlloc = mremap(pProgram, ProgramAllocSize, ProgramAllocSize, MREMAP_MAYMOVE);
			if(pAlloc == MAP_FAILED) // this could be anything, need to check errno...
				ERROR(2, "out of memory\n");

			pProgram = pAlloc;
		}
	}

	// '[' ']' derp
	if(Stack.Size)
		ERROR(3, "parsing of input failed\n");

	Stack_Destroy(pStack);

	// clean return
	memcpy(&pProgram[ProgramSize], aInstReturnNormal, sizeof(aInstReturnNormal));
	ProgramSize += sizeof(aInstReturnNormal);

	*pProgramAllocSize = ProgramAllocSize;

	// make executable
	mprotect(pProgram, ProgramAllocSize, PROT_READ | PROT_EXEC);

	return pProgram;
}
/*
Breakpoint Idee:
mov breakpoint-num, eax
mov [esp], ebx
call ebx

Springt zu nach dem brainfuck code aufruf.
((int(*)())pProgram)();
2 x stack pop'n für 2 instruction pointer

return code anschauen:
0 normal
> 0 id vom breakpoint
*/
#endif

int main(int argc, char *argv[])
{
	// Interactive mode
	if(argc == 1)
	{
		CCommand aCommands[] =
		{
			{"load", CMD_load},
			{"run", CMD_run},
			{"eval", CMD_eval},
			{"break", CMD_break},
			{"step", CMD_step},
			{"memory", CMD_memory},
			{"show", CMD_show},
			{"change", CMD_change},
			{"quit", CMD_quit},
			{0, 0}
		};

		CBrainfuckContext Context;
		BrainfuckContext_Init(&Context, 0, 0);

		while(1)
		{
			printf("esp> ");
			char aBuf[PATH_MAX + 16];
			size_t Length;

			if(fgets(aBuf, sizeof(aBuf), stdin) == 0) // EOF
				CMD_quit(&Context, 0, 0);

			Length = strlen(aBuf) - 1;
			aBuf[Length] = 0; // Eat trailing '\n'

			CommandLine(&Context, &aCommands[0], aBuf);
		}
	}
	// Execution mode
	else if(argc >= 3)
	{
		if(strcmp(argv[1], "-e"))
			ERROR(1, "usage: ./assa [-e brainfuck_filnename]\n");

		char *pProgram;
		size_t ProgramSize;
		ProgramSize = LoadProgram(argv[2], &pProgram);

#ifdef BONUS
		size_t DataAllocSize = MEMPAGESIZE * 16 + MEMPAGESIZE;
		unsigned char *pData = mmap(0, DataAllocSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if(pData == MAP_FAILED)
			ERROR(2, "out of memory\n");
		unsigned char *pDataStart = pData;

		// Set up trap
		mprotect(pData + DataAllocSize - MEMPAGESIZE, MEMPAGESIZE, PROT_NONE);

		// install SIGSEGV trap
		// this is used to detect invalid memory access
		struct sigaction SigAction;
		memset(&SigAction, 0, sizeof(SigAction));
		sigemptyset(&SigAction.sa_mask);
		SigAction.sa_sigaction = SIGSEGV_Handler;
		SigAction.sa_flags = SA_SIGINFO;
		sigaction(SIGSEGV, &SigAction, NULL);

		// Hack to avoid global vars
		SIGSEGV_Handler(-1, (void *)&pDataStart, (void *)&DataAllocSize);

		size_t BinaryAllocSize;
		unsigned char *pBinary;
		pBinary = JITCompileBrainfuck(pProgram, ProgramSize, &BinaryAllocSize);

		int Ret;
		// mov  edx, [ebp+pData]
		// ^ intel syntax
		// v gas syntax
		asm("mov %[pData], %%edx"
				:: [pData] "m" (pData) : "edx");

		Ret = ((int(*)())pBinary)();

		// mov  [ebp+pData], edx ; Fix data pointer
		// ^ intel syntax
		// v gas syntax
		asm("mov %%edx, %[pData]"
				: [pData] "=r" (pData) :: "edx");

		munmap(pDataStart, DataAllocSize);
		munmap(pBinary, BinaryAllocSize);
#else
		uint32_t *pJumpTable;
		BuildJumpTable(pProgram, ProgramSize, &pJumpTable);

		CBrainfuckContext Context;
		BrainfuckContext_Init(&Context, pProgram, pJumpTable);

		RunBrainfuck(&Context);

		free(pProgram);
		free(Context.pDataStart);
		free(pJumpTable);
#endif
	}
	else
		ERROR(1, "usage: ./assa [-e brainfuck_filnename]\n");

	return 0;
}
