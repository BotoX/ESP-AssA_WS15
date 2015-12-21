//-----------------------------------------------------------------------------
// assa_.c
//
// Brainfuck interpreter
// Compile with -O3 or christmas won't happen this year
//
//-----------------------------------------------------------------------------
//

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

// Uncomment for bonus
//#define BONUS
#ifdef BONUS
	#include <sys/mman.h>
	#include <unistd.h>
	#define MEMPAGESIZE sysconf(_SC_PAGE_SIZE)
	#define MEMPAGEMASK ~(MEMPAGESIZE - 1)

	#include <signal.h>
	#include <ucontext.h>
#endif

// Data Types
typedef struct
{
	uint32_t *pData;
	size_t Size;
	size_t AllocSize;
} CStack;

typedef struct
{
	uint32_t Position;
	char *pProgram;
	size_t ProgramSize;

	uint32_t *pJumpTable;

	uint32_t *pBreakPoints;
	size_t BreakPointsSize;
	char *pBreakPointsBackup;

	unsigned char *pDataStart;
	unsigned char *pData;
	size_t DataSize;
	size_t DataAllocSize;
} CBrainfuckContext;

typedef int (*pfnCommand)(CBrainfuckContext *pContext, int argc, char *argv[]);
typedef struct
{
	const char *pCmd;
	pfnCommand pfnCmd;
} CCommand;

// Function prototypes

//-----------------------------------------------------------------------------
///
/// Prints an error message to stdout and exits depending on initialization.
/// First call to function is initialization, Error code represents mode.
///
/// @param Error Error code / return code.
/// @param pMessage Error message.
///
/// @return void
//
void error(int Error, const char *pMessage);

//-----------------------------------------------------------------------------
///
/// Allocate or grow memory for a stack.
///
/// @param pStack Pointer to CStack object.
/// @param Size Size to allocate.
///
/// @return void
//
void Stack_Alloc(CStack *pStack, size_t Size);

//-----------------------------------------------------------------------------
///
/// Create a new stack.
///
/// @param pStack Pointer to CStack object.
/// @param StartSize Size to initially allocate.
///
/// @return void
//
void Stack_Init(CStack *pStack, size_t StartSize);

//-----------------------------------------------------------------------------
///
/// Destroy a given stack.
///
/// @param pStack Pointer to CStack object.
///
/// @return void
//
void Stack_Destroy(CStack *pStack);

//-----------------------------------------------------------------------------
///
/// Push Element onto stack.
///
/// @param pStack Pointer to CStack object.
/// @param Element Element to push onto stack.
///
/// @return void
//
void Stack_Push(CStack *pStack, uint32_t Element);

//-----------------------------------------------------------------------------
///
/// Pop Element from stack.
///
/// @param pStack Pointer to CStack object.
///
/// @return The Element pop'd or UINT32_MAX if the stack is empty.
//
uint32_t Stack_Pop(CStack *pStack);

int CMD_load(CBrainfuckContext *pContext, int argc, char *argv[]);
int CMD_run(CBrainfuckContext *pContext, int argc, char *argv[]);
int CMD_eval(CBrainfuckContext *pContext, int argc, char *argv[]);
int CMD_break(CBrainfuckContext *pContext, int argc, char *argv[]);
int CMD_step(CBrainfuckContext *pContext, int argc, char *argv[]);
int CMD_memory(CBrainfuckContext *pContext, int argc, char *argv[]);
int CMD_show(CBrainfuckContext *pContext, int argc, char *argv[]);
int CMD_change(CBrainfuckContext *pContext, int argc, char *argv[]);
int CMD_quit(CBrainfuckContext *pContext, int argc, char *argv[]);

//-----------------------------------------------------------------------------
///
/// Parses and executes a command line command.
///
/// @param pContext Pointer to CBrainfuckContext object.
/// @param pCommand Pointer to first CCommand object in a null-terminated array.
/// @param pLine String to evaluate.
///
/// @return Returnvale of executed command or -1 if none is found.
//
int CommandLine(CBrainfuckContext *pContext, CCommand *pCommand, char *pLine);

//-----------------------------------------------------------------------------
///
/// Loads a file into memory and filters invalid characters from it.
///
/// @param pFilename Path of the file.
/// @param ppProgram Pointer to string which will hold the result.
///
/// @return Length of ppProgram.
//
size_t LoadProgram(const char *pFilename, char **ppProgram);

//-----------------------------------------------------------------------------
///
/// Initializes a new CBrainfuckContext object.
///
/// @param pContext Pointer to CBrainfuckContext object.
/// @param pProgram Brainfuck program string.
/// @param pJumpTable Brainfuck program jumptable.
///
/// @return void
//
void BrainfuckContext_Init(CBrainfuckContext *pContext, char *pProgram, uint32_t *pJumpTable);

//-----------------------------------------------------------------------------
///
/// Initializes data memory for the CBrainfuckContext object.
///
/// @param pContext Pointer to CBrainfuckContext object.
///
/// @return void
//
void BrainfuckContext_InitData(CBrainfuckContext *pContext);

#ifdef BONUS
//-----------------------------------------------------------------------------
///
/// Segmentation fault signal handler.
///
/// @param Signal Signal that invoked us (always SIGSEGV or not SIGSEGV for init).
/// @param pSignal Pointer to siginfo_t object.
/// @param pArg Pointer to unkown object. On Linux ucontext_t.
///
/// @return void
//
static void SIGSEGV_Handler(int Signal, siginfo_t *pSignal, void *pArg);

//-----------------------------------------------------------------------------
///
/// "Compiles" Brainfuck code into optimized x86 machine code.
/// Breakpoint Idea (doesn't make sense with current optimizing code)
/// not implemented but should work™
///
/// mov  breakpoint-num, eax
/// mov  [esp], ebx
/// call  ebx
///
/// Look at return code (eax)
/// 0 = program exited normaly, no breakpoint occured.
/// >0 = above assembler has been executed, read on.
///
/// Jumps to instruction after brainfuck code invocation ((int(*)())pBinary)();
/// Pop stack once to get EIP (instruction pointer) of next instruction
/// where program returned because of a breakpoint.
/// Pop stack second time to get rid of previous EIP on stack.
/// Can use first pop'd EIP to jump back into brainfuck program afterwards.
///
/// @param pBuf Brainfuck program.
/// @param Length Length of pBuf.
/// @param pProgramAllocSize Pointer to variable which will hold the size of
///							 the compiled program.
///
/// @return Pointer to compiled program.
//
unsigned char *JITCompileBrainfuck(char *pBuf, size_t Length, size_t *pProgramAllocSize);
#endif

//-----------------------------------------------------------------------------
///
/// Builds (precomputes) jump table for brainfuck program.
///
/// O(1) implementation
/// This would be a lot more memory efficient by using something like a Y-fast trie
/// https://en.wikipedia.org/wiki/Y-fast_trie
/// (which'd be wayyyy too much effort for me to implement for this assignment - or at all)
/// so basically use this great library: http://www.nedprod.com/programs/portable/nedtries/
/// in case of hanoi.bf this will use about 218k memory
///
/// @param pBuf Brainfuck program.
/// @param Length Length of pBuf.
/// @param ppJumpTable Pointer to JumpTable which will hold the result.
///
/// @return non-zero on failure
//
int BuildJumpTable(char *pBuf, size_t Length, uint32_t **ppJumpTable);

//-----------------------------------------------------------------------------
///
/// Runs a given CBrainfuckContext object.
///
/// @param pContext Pointer to CBrainfuckContext object.
/// @param steps Number of steps to execute or 0 to run the full program.
///
/// @return Position of the instruction pointer.
//
uint32_t RunBrainfuck(CBrainfuckContext *pContext, size_t Steps);

//------------------------------------------------------------------------------
///
/// The main program.
/// Provides functionality as described by:
/// https://palme.iicm.tugraz.at/wiki/ESP/AssA_WS15
///
/// @param argc 1 for interactive mode or >3 for execution mode "-e filename".
/// @param argv arguments
///
/// @return non-zero on failure
//
int main(int argc, char *argv[]);

void error(int Error, const char *pMessage)
{
	static char Initialized = 0;
	// Mode = 0 "-e" -> exit on error
	// Mode = 1 -> interactive, only exit on errorcode 2
	static char Mode = 0;
	if(!Initialized)
	{
		Initialized = 1;
		Mode = Error;
		return;
	}

	printf(pMessage);

	if(!Mode || Error == 2)
		exit(Error);
}

#ifdef BONUS
	static void SIGSEGV_Handler(int Signal, siginfo_t *pSignal, void *pArg)
	{
		// Hack to avoid global vars
		static unsigned char **ppDataStart = 0;
		static size_t *pDataAllocSize = 0;
		if(Signal != SIGSEGV)
		{
			ppDataStart = (unsigned char **)pSignal;
			pDataAllocSize = (size_t *)pArg;
			return;
		}

		// previous execution context
		ucontext_t *pContext = pArg;

		// edx register from crashed execution context is the current pData pointer
		unsigned char *pData = (unsigned char *)pContext->uc_mcontext.gregs[REG_EDX];

		// calc offset using pDataStart
		size_t DataOffset = pData - *ppDataStart;

		// reset locked memory page protection
		mprotect(*ppDataStart, *pDataAllocSize + MEMPAGESIZE, PROT_READ | PROT_WRITE);

		// allocate another memory page for data
		void *pAlloc = mremap(*ppDataStart, *pDataAllocSize, *pDataAllocSize + MEMPAGESIZE, MREMAP_MAYMOVE);
		if(pAlloc == MAP_FAILED) // this could be anything, need to check errno...
			error(2, "[ERR] out of memory\n");

		// fix variables in main
		*pDataAllocSize += MEMPAGESIZE;
		*ppDataStart = pAlloc;

		// lock next memory page again so we can catch the next invalid memory access
		mprotect(*ppDataStart - (*pDataAllocSize + MEMPAGESIZE), MEMPAGESIZE, PROT_NONE);

		// calculate correct data pointer in new memory region (since it could've moved)
		pData = *ppDataStart + DataOffset;

		// put new data pointer into edx register
		pContext->uc_mcontext.gregs[REG_EDX] = (uintptr_t)pData;

		// restore execution at failed instruction, yay \o/
		setcontext(pContext);
	}
#endif


/* CStack */
void Stack_Alloc(CStack *pStack, size_t Size)
{
	if(pStack->AllocSize == 0)
	{
		pStack->AllocSize = Size;
		pStack->pData = malloc(pStack->AllocSize * sizeof(size_t));
		if(!pStack->pData)
			error(2, "[ERR] out of memory\n");
	}
	else
	{
		pStack->AllocSize += Size;
		void *pAlloc = realloc(pStack->pData, pStack->AllocSize * sizeof(size_t));
		if(!pStack->pData)
		{
			free(pStack->pData);
			error(2, "[ERR] out of memory\n");
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

void Stack_Push(CStack *pStack, uint32_t Element)
{
	if(pStack->Size >= pStack->AllocSize)
		Stack_Alloc(pStack, 32);

	pStack->pData[pStack->Size++] = Element;
}

uint32_t Stack_Pop(CStack *pStack)
{
	if(pStack->Size == 0)
		return UINT32_MAX;

	return pStack->pData[--pStack->Size];
}
/* CStack */

/* Console */
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
		pContext->Position = 0;

		free(pContext->pJumpTable);
		pContext->pJumpTable = 0;

		if(pContext->pBreakPoints)
		{
			free(pContext->pBreakPoints);
			pContext->pBreakPoints = 0;

			if(pContext->pBreakPointsBackup)
			{
				free(pContext->pBreakPointsBackup);
				pContext->pBreakPointsBackup = 0;
			}
		}
	}

	if(pContext->pData)
	{
		free(pContext->pDataStart);
		pContext->pData = 0;
		pContext->pDataStart = 0;
		pContext->DataSize = 0;
	}

	pContext->ProgramSize = LoadProgram(argv[1], &pContext->pProgram);
	if(!pContext->ProgramSize)
		return 1;

	if(BuildJumpTable(pContext->pProgram, pContext->ProgramSize, &pContext->pJumpTable))
	{
		free(pContext->pProgram);
		pContext->pProgram = 0;
		return 1;
	}

	return 0;
}

int CMD_run(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(!pContext->pProgram)
	{
		printf("[ERR] no program loaded\n");
		return 1;
	}

	size_t Steps = 0;
	if(argc == -1)
		Steps = *((size_t *)argv);

	if(!pContext->pData)
		BrainfuckContext_InitData(pContext);

	if(pContext->pBreakPoints)
	{
		size_t i;
		if(!pContext->pBreakPointsBackup)
		{
			// Create array for storing original instructions
			pContext->pBreakPointsBackup = malloc(pContext->BreakPointsSize);
			if(!pContext->pBreakPointsBackup)
				error(2, "[ERR] out of memory\n");

			for(i = 0; i < pContext->BreakPointsSize; i++)
			{
				// Ignore breakpoints which have already been passed
				if(pContext->pBreakPoints[i] == UINT32_MAX)
					continue;

				// Position of breakpoint in pProgram
				uint32_t Position = pContext->pBreakPoints[i];

				// Save original instruction ...
				pContext->pBreakPointsBackup[i] = pContext->pProgram[Position];
				// ... and overwrite with 0, causing RunBrainfuck to return at <Position>
				pContext->pProgram[Position] = 0;
			}
		}

		uint32_t ReturnCode = RunBrainfuck(pContext, Steps);

		// Program ended
		if(ReturnCode == pContext->ProgramSize)
		{
			// Restore original program (in case we didn't hit a breakpoint we've set)
			for(i = 0; i < pContext->BreakPointsSize; i++)
			{
				if(pContext->pBreakPoints[i] == UINT32_MAX)
					continue;

				uint32_t Position = pContext->pBreakPoints[i];

				pContext->pProgram[Position] = pContext->pBreakPointsBackup[i];
			}

			free(pContext->pBreakPoints);
			pContext->pBreakPoints = 0;

			free(pContext->pBreakPointsBackup);
			pContext->pBreakPointsBackup = 0;
		}
		else if(ReturnCode == UINT32_MAX) // Stopped because of step
		{
			return 0;
		}
		else // Stopped at breakpoint
		{
			uint32_t BreakPoint = 0;
			for(i = 0; i < pContext->BreakPointsSize; i++)
			{
				// Find the pBreakPoints array index which made our program return ...
				if(pContext->pBreakPoints[i] == ReturnCode)
				{
					BreakPoint = i;
					break;
				}
			}

			// ... and restore the original instruction
			pContext->pProgram[ReturnCode] = pContext->pBreakPointsBackup[BreakPoint];
			// Delete breakpoint so we don't use it again
			pContext->pBreakPoints[BreakPoint] = UINT32_MAX;

			return 0;
		}
	}
	else
	{
		// Stopped early because of step, don't free program
		if(RunBrainfuck(pContext, Steps) == UINT32_MAX)
			return 0;
	}

	free(pContext->pProgram);
	pContext->pProgram = 0;
	pContext->Position = 0;

	free(pContext->pJumpTable);
	pContext->pJumpTable = 0;

	return 0;
}

int CMD_eval(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("[ERR] wrong parameter count\n");
		return 1;
	}

	if(!pContext->pData)
		BrainfuckContext_InitData(pContext);

	// Store original context
	CBrainfuckContext OldContext;
	memcpy(&OldContext, pContext, sizeof(CBrainfuckContext));

	// load new program
	pContext->pProgram = argv[1];
	pContext->ProgramSize = strlen(argv[1]);
	pContext->Position = 0;
	pContext->pJumpTable = 0;

	BuildJumpTable(pContext->pProgram, pContext->ProgramSize, &pContext->pJumpTable);
	RunBrainfuck(pContext, 0);

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
	if(Temp < 0 || Temp > pContext->ProgramSize)
		return 1;

	uint32_t BreakPoint = Temp;
	if(!pContext->pBreakPoints)
	{
		pContext->BreakPointsSize = 1;
		pContext->pBreakPoints = malloc(pContext->BreakPointsSize * sizeof(uint32_t));
		if(!pContext->pBreakPoints)
			error(2, "[ERR] out of memory\n");
	}
	else
	{
		// Avoid duplicate breakpoints
		size_t i;
		for(i = 0; i < pContext->BreakPointsSize; i++)
		{
			if(pContext->pBreakPoints[i] == BreakPoint)
				return 1;
		}

		if(pContext->pBreakPointsBackup)
		{
			// Restore original program first
			for(i = 0; i < pContext->BreakPointsSize; i++)
			{
				if(pContext->pBreakPoints[i] == UINT32_MAX)
					continue;

				uint32_t Position = pContext->pBreakPoints[i];

				pContext->pProgram[Position] = pContext->pBreakPointsBackup[i];
			}

			// reset pBreakPointsBackup so CMD_run builds it again and etc.
			free(pContext->pBreakPointsBackup);
			pContext->pBreakPointsBackup = 0;
		}

		// Allocate memory for new breakpoint
		pContext->BreakPointsSize += 1;
		void *pAlloc = realloc(pContext->pBreakPoints, pContext->BreakPointsSize * sizeof(uint32_t));
		if(!pAlloc)
			error(2, "[ERR] out of memory\n");

		pContext->pBreakPoints = pAlloc;
	}

	pContext->pBreakPoints[pContext->BreakPointsSize - 1] = BreakPoint;

	return 0;
}

int CMD_step(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(!pContext->pProgram)
	{
		printf("[ERR] no program loaded\n");
		return 1;
	}

	size_t Steps = 1;
	if(argc >= 2)
	{
		long int Temp = strtol(argv[1], 0, 10);
		if(Temp <= 0)
			return 1;

		Steps = Temp;
	}

	return CMD_run(pContext, -1, (void *)&Steps);
}

int CMD_memory(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(!pContext->pData)
	{
		printf("[ERR] no program loaded\n");
		return 1;
	}

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
			*pBuf = 0;

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

	size_t i;
	// Restore original program first
	for(i = 0; i < pContext->BreakPointsSize; i++)
	{
		if(pContext->pBreakPoints[i] == UINT32_MAX)
			continue;

		uint32_t Position = pContext->pBreakPoints[i];

		pContext->pProgram[Position] = pContext->pBreakPointsBackup[i];
	}

	// Print <Size> amount of characters
	printf("%.*s\n", Size, &pContext->pProgram[pContext->Position]);

	// Restore breakpoints again
	for(i = 0; i < pContext->BreakPointsSize; i++)
	{
		if(pContext->pBreakPoints[i] == UINT32_MAX)
			continue;

		uint32_t Position = pContext->pBreakPoints[i];

		pContext->pProgram[Position] = 0;
	}

	return 0;
}

int CMD_change(CBrainfuckContext *pContext, int argc, char *argv[])
{
	if(!pContext->pData)
	{
		printf("[ERR] no program loaded\n");
		return 1;
	}

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
	char Found = 1;
	char InString = 0;

	while(*pLine)
	{
		if(*pLine == '"' && *(pLine - 1) != '\\')
		{
			*pLine = 0;
			InString ^= 1;
			if(InString)
			{
				pLine++;
				Found = 1;
			}
		}

		if((*pLine == ' ' || *pLine == '\t') && !InString)
		{
			*pLine = 0;
			Found = 1;
		}
		else if(Found)
		{
			if(Argc < sizeof(apArgv)/sizeof(*apArgv))
			{
				apArgv[Argc++] = pLine;
				Found = 0;
			}
			else // ignore additional parameters
				break;
		}
		pLine++;
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

size_t LoadProgram(const char *pFilename, char **ppProgram)
{
	char *pFileData;
	FILE *pFile;
	pFile = fopen(pFilename, "rb");
	if(!pFile)
	{
		error(4, "[ERR] reading the file failed\n");
		return 0;
	}

	size_t FileSize;
	fseek(pFile, 0, SEEK_END);
	FileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	pFileData = malloc(FileSize + 1);
	if(!pFileData)
		error(2, "[ERR] out of memory\n");

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
		error(2, "[ERR] out of memory\n");

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

void BrainfuckContext_Init(CBrainfuckContext *pContext, char *pProgram, uint32_t *pJumpTable)
{
	memset(pContext, 0, sizeof(CBrainfuckContext));
	pContext->pProgram = pProgram;

	pContext->pData = 0;
	pContext->pDataStart = 0;
	pContext->DataAllocSize = 1024;
	pContext->DataSize = 0;

	pContext->pJumpTable = pJumpTable;
	pContext->pBreakPoints = 0;
	pContext->BreakPointsSize = 0;
	pContext->pBreakPointsBackup = 0;
}

void BrainfuckContext_InitData(CBrainfuckContext *pContext)
{
	pContext->pDataStart = malloc(pContext->DataAllocSize);
	pContext->DataSize = pContext->DataAllocSize;
	pContext->pData = pContext->pDataStart;
	memset(pContext->pData, 0, pContext->DataSize);

	if(!pContext->pData)
		error(2, "[ERR] out of memory\n");
}

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
		error(2, "[ERR] out of memory\n");

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
					error(3, "[ERR] parsing of input failed\n");

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
			void *pAlloc = mremap(pProgram, ProgramAllocSize, ProgramAllocSize + MEMPAGESIZE, MREMAP_MAYMOVE);
			if(pAlloc == MAP_FAILED) // this could be anything, need to check errno...
				error(2, "[ERR] out of memory\n");

			ProgramAllocSize += MEMPAGESIZE;
			pProgram = pAlloc;
		}
	}

	// '[' ']' derp
	if(Stack.Size)
		error(3, "[ERR] parsing of input failed\n");

	Stack_Destroy(pStack);

	// clean return
	memcpy(&pProgram[ProgramSize], aInstReturnNormal, sizeof(aInstReturnNormal));
	ProgramSize += sizeof(aInstReturnNormal);

	*pProgramAllocSize = ProgramAllocSize;

	// make executable
	mprotect(pProgram, ProgramAllocSize, PROT_READ | PROT_EXEC);

	return pProgram;
}
#endif

int BuildJumpTable(char *pBuf, size_t Length, uint32_t **ppJumpTable)
{
	CStack Stack;
	CStack *pStack = &Stack;

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
	{
		error(3, "[ERR] parsing of input failed\n");
		return 1;
	}

	uint32_t *pJumpTable = malloc(LastBracket * sizeof(uint32_t));
	if(!pJumpTable)
		error(2, "[ERR] out of memory\n");

	memset(pJumpTable, 0, LastBracket * sizeof(uint32_t));

	Stack_Init(pStack, 32);

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

				// '[' jumps to previously push'd ']' position
				pJumpTable[i] = Jump;
				// previously push'd '[' jumps to this ']'
				pJumpTable[Jump] = i;
			} break;
		}
	}

	Stack_Destroy(pStack);

	*ppJumpTable = pJumpTable;

	return 0;
}

// This is so horrible, I'm sorry :(((
// But duplicating code is forbidden, goto is forbidden
// I was left with no other choice D:
// (except sacrificing performance obv. :p)
#define MACRO_RUN_BRAINFUCK_FUNC() \
	switch(*pProgram) \
	{ \
		case '>': \
		{ \
			pData++; \
 \
			/* Boundary overflow check */ \
			if(pData >= pDataEnd) \
			{ \
				pContext->DataSize += pContext->DataAllocSize; \
				void *pAlloc = realloc(pContext->pDataStart, pContext->DataSize); \
				if(!pAlloc) \
					error(2, "[ERR] out of memory\n"); \
 \
				pData = pAlloc + (pData - pContext->pDataStart); \
				pContext->pDataStart = pAlloc; \
				pDataEnd = pContext->pDataStart + pContext->DataSize; \
				memset(pData, 0, pDataEnd - pData); \
			} \
		} break; \
		case '<': \
		{ \
			pData--; \
			/* underflow ignored */ \
		} break; \
		case '+': \
		{ \
			(*pData)++; \
		} break; \
		case '-': \
		{ \
			(*pData)--; \
		} break; \
		case '.': \
		{ \
			putchar(*pData); \
		} break; \
		case ',': \
		{ \
			*pData = getchar(); \
		} break; \
		case '[': \
		{ \
			if(!*pData) \
				pProgram = pProgramStart + pJumpTable[pProgram - pProgramStart] - 1; \
		} break; \
		case ']': \
		{ \
			if(*pData) \
				pProgram = pProgramStart + pJumpTable[pProgram - pProgramStart] - 1; \
		} break; \
		default: \
		{ \
			pContext->Position = pProgram - pProgramStart; \
			pContext->pData = pData; \
 \
			return pContext->Position; \
		} break; \
	}

uint32_t RunBrainfuck(CBrainfuckContext *pContext, size_t Steps)
{
	// gcc can't into optimizing >_>
	register const char *pProgramStart = pContext->pProgram;
	register const char *pProgram = pContext->pProgram + pContext->Position;
	register unsigned char *pData = pContext->pData;
	register unsigned char *pDataEnd = pContext->pDataStart + pContext->DataSize;
	register uint32_t *pJumpTable = pContext->pJumpTable;

	if(!Steps)
	{
		for(;; pProgram++)
		{
			MACRO_RUN_BRAINFUCK_FUNC()
		}
	}
	else
	{
		for(; Steps--; pProgram++)
		{
			MACRO_RUN_BRAINFUCK_FUNC()
		}
		pContext->Position = pProgram - pProgramStart;
		pContext->pData = pData;

		return UINT32_MAX;
	}
}

int main(int argc, char *argv[])
{
	// Interactive mode
	if(argc == 1)
	{
		// Init error func to interactive mode
		error(1, 0);

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
		// Init error func to execution mode
		error(0, 0);

		if(strcmp(argv[1], "-e"))
			error(1, "[ERR] usage: ./assa [-e brainfuck_filnename]\n");

		char *pProgram;
		size_t ProgramSize;
		ProgramSize = LoadProgram(argv[2], &pProgram);

#ifdef BONUS
		size_t DataAllocSize = MEMPAGESIZE + MEMPAGESIZE;
		unsigned char *pData = mmap(0, DataAllocSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if(pData == MAP_FAILED)
			error(2, "[ERR] out of memory\n");
		unsigned char *pDataStart = pData;

		// Set up memory trap
		mprotect(pData + (DataAllocSize - MEMPAGESIZE), MEMPAGESIZE, PROT_NONE);

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

		free(pProgram);

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

		// supress unused variable
		(void)Ret;

		munmap(pDataStart, DataAllocSize);
		munmap(pBinary, BinaryAllocSize);
#else
		uint32_t *pJumpTable;
		BuildJumpTable(pProgram, ProgramSize, &pJumpTable);

		CBrainfuckContext Context;
		BrainfuckContext_Init(&Context, pProgram, pJumpTable);
		BrainfuckContext_InitData(&Context);

		RunBrainfuck(&Context, 0);

		free(pProgram);
		free(Context.pDataStart);
		free(pJumpTable);
#endif
	}
	else
		error(1, "[ERR] usage: ./assa [-e brainfuck_filnename]\n");

	return 0;
}
