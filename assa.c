//-----------------------------------------------------------------------------
// assa.c
//
// Brainfuck interpreter
//
//-----------------------------------------------------------------------------
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERROR(error, fmt, ...) \
	do { \
		fprintf(/*stderr*/stdout, "[ERR] " fmt, ##__VA_ARGS__); \
		exit(error); \
	} while(0)


/*
 * Due to language constraints I had to implement a few things first
 * in order to efficiently create a brainfuck interpreter.
 *
 * The following code is not part of the assignment and should not be
 * discussed during the assignment interview.
 */
/* CKVMap */
typedef struct
{
	int Key;
	int Value;
} CKVMap;

typedef struct
{
	CKVMap ***pppKVMap;
	size_t Size;
	size_t AllocSize;
	size_t StartSize;
} __CKVMapInternal;

int KVMap_CompareFn(const void *pL, const void *pR)
{
	const CKVMap *pLeft = *(CKVMap **)pL;
	const CKVMap *pRight = *(CKVMap **)pR;

	return pLeft->Key - pRight->Key;
}

void KVMap_Alloc(__CKVMapInternal *pKVMapInternal, size_t Size)
{
	if(pKVMapInternal->AllocSize == 0)
	{
		pKVMapInternal->AllocSize = Size;
		*pKVMapInternal->pppKVMap = malloc((pKVMapInternal->AllocSize + 1) * sizeof(void *));
		if(!pKVMapInternal->pppKVMap)
			ERROR(2, "out of memory\n");

		// Magic
		(*pKVMapInternal->pppKVMap)[0] = (void *)pKVMapInternal;
		// This one is tricky: we don't add sizeof(pointer) to the pointer to shift it forward by one
		// but add 1 to it since the compiler will automatically shift sizeof(pointer) because of the datatype
		*pKVMapInternal->pppKVMap += 1;
	}
	else
	{
		CKVMap **ppAlloc;
		pKVMapInternal->AllocSize += Size;

		// realloc needs to happen on the original malloc'd chunk
		*pKVMapInternal->pppKVMap -= 1;

		ppAlloc = realloc(*pKVMapInternal->pppKVMap, (pKVMapInternal->AllocSize + 1) * sizeof(void *));
		if(!ppAlloc)
		{
			free(*pKVMapInternal->pppKVMap);
			ERROR(2, "out of memory\n");
		}

		*pKVMapInternal->pppKVMap = ppAlloc;
		*pKVMapInternal->pppKVMap += 1;
	}
}

void KVMap_Init(CKVMap ***pppKVMap, size_t StartSize)
{
	__CKVMapInternal *pKVMapInternal = malloc(sizeof(__CKVMapInternal));
	pKVMapInternal->Size = 0;
	pKVMapInternal->AllocSize = 0;
	pKVMapInternal->StartSize = StartSize;
	pKVMapInternal->pppKVMap = pppKVMap;
	KVMap_Alloc(pKVMapInternal, StartSize);
}

CKVMap *KVMap_New()
{
	CKVMap *pKVMap = malloc(sizeof(CKVMap));
	if(!pKVMap)
		ERROR(2, "out of memory\n");

	return pKVMap;
}

void KVMap_Sort(CKVMap **ppKVMap)
{
	__CKVMapInternal *pKVMapInternal = (__CKVMapInternal *)(ppKVMap[-1]);
	qsort(ppKVMap, pKVMapInternal->Size, sizeof(void *), KVMap_CompareFn);
}

CKVMap *KVMap_Search(CKVMap **ppKVMap, int Key)
{
	__CKVMapInternal *pKVMapInternal = (__CKVMapInternal *)(ppKVMap[-1]);

	CKVMap Temp;
	Temp.Key = Key;
	CKVMap *pTemp = &Temp;

	CKVMap **ppResult = bsearch(&pTemp, ppKVMap, pKVMapInternal->Size, sizeof(void *), KVMap_CompareFn);
	if(!ppResult)
		return 0;
	else
		return *ppResult;
}

int KVMap_Insert(CKVMap ***pppKVMap, int Key, int Value)
{
	CKVMap **ppKVMap = *pppKVMap;
	__CKVMapInternal *pKVMapInternal = (__CKVMapInternal *)(ppKVMap[-1]);
	if(pKVMapInternal->Size >= pKVMapInternal->AllocSize)
	{
		KVMap_Alloc(pKVMapInternal, pKVMapInternal->StartSize);
		// Update pointers, the memory (could've) moved
		ppKVMap = *pppKVMap;
		pKVMapInternal = (__CKVMapInternal *)(ppKVMap[-1]);
	}

	CKVMap *pKVMap = KVMap_New();
	pKVMap->Key = Key;
	pKVMap->Value = Value;

	ppKVMap[pKVMapInternal->Size] = pKVMap;
	return pKVMapInternal->Size++;
}

void KVMap_Destroy(CKVMap ***pppKVMap)
{
	CKVMap **ppKVMap = *pppKVMap;
	__CKVMapInternal *pKVMapInternal = (__CKVMapInternal *)(ppKVMap[-1]);

	// Free all Elements of the map
	int i;
	for(i = 0; i < pKVMapInternal->Size; i++)
		free(ppKVMap[i]);

	// Free the map itself (pointer array)
	free(&ppKVMap[-1]);

	// And the __CKVMapInternal that was prepended
	free(pKVMapInternal);

	*pppKVMap = 0;
}
/* CKVMap */

/* CStack */
typedef struct
{
	int *pData;
	size_t Size;
	size_t AllocSize;
} CStack;

void Stack_Alloc(CStack *pStack, size_t Size)
{
	if(pStack->AllocSize == 0)
	{
		pStack->AllocSize = Size;
		pStack->pData = malloc(pStack->AllocSize * sizeof(CStack));
		if(!pStack->pData)
			ERROR(2, "out of memory\n");
	}
	else
	{
		int *pAlloc;
		pStack->AllocSize += Size;
		pAlloc = realloc(pStack->pData, pStack->AllocSize * sizeof(CStack));
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
	Stack_Alloc(pStack, StartSize);
}

void Stack_Destroy(CStack *pStack)
{
	pStack->Size = 0;
	pStack->AllocSize = 0;
	free(pStack->pData);
}

int Stack_Top(CStack *pStack)
{
	if(pStack->Size == 0)
		return -1;

	return pStack->pData[pStack->Size - 1];
}

int Stack_Push(CStack *pStack, int Element)
{
	if(pStack->Size >= pStack->AllocSize)
		Stack_Alloc(pStack, 32);

	pStack->pData[pStack->Size++] = Element;
	return Element;
}

int Stack_Pop(CStack *pStack)
{
	if(pStack->Size == 0)
		return -1;

	return pStack->pData[--pStack->Size];
}
/* CStack */



long int LoadFile(const char *pFilename, char **ppFileData)
{
	FILE *pFile;
	pFile = fopen(pFilename, "rb");
	if(!pFile)
		ERROR(4, "reading the file failed\n");

	long int FileSize;
	fseek(pFile, 0, SEEK_END);
	FileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	*ppFileData = malloc(FileSize + 1);
	if(!*ppFileData)
		ERROR(2, "out of memory\n");

	fread(*ppFileData, 1, FileSize, pFile),

	fclose(pFile);

	(*ppFileData)[FileSize] = 0;

	return FileSize;
}

char *CompileBrainfuck(char *pBuf, long int Length, CKVMap ***pppJumpTable)
{
	int RealLength = 0;
	CStack Stack;
	CStack *pStack = &Stack;
	Stack_Init(pStack, 32);

	KVMap_Init(pppJumpTable, 32);

	// Filter code and build jump table
	long int i;
	for(i = 0; i < Length; i++)
	{
		switch(pBuf[i])
		{
			case '>':
			case '<':
			case '+':
			case '-':
			case '.':
			case ',':
			{
				RealLength++;
			} break;

			case '[':
			{
				Stack_Push(pStack, RealLength);
				RealLength++;
			} break;

			case ']':
			{
				int Jump = Stack_Pop(pStack);
				if(Jump == -1)
					ERROR(3, "parsing of input failed\n");

				KVMap_Insert(pppJumpTable, RealLength, Jump);
				KVMap_Insert(pppJumpTable, Jump, RealLength);

				RealLength++;
			} break;
		}
	}

	// '[' ']' derp
	if(Stack.Size)
		ERROR(3, "parsing of input failed\n");

	Stack_Destroy(pStack);
	KVMap_Sort(*pppJumpTable);

	// Allocate memory for the filtered code
	char *pProgram = malloc(RealLength + 1);
	if(!pProgram)
		ERROR(2, "out of memory\n");

	// And copy only the valid characters
	int j;
	for(i = 0, j = 0; i < Length; i++)
	{
		switch(pBuf[i])
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
				pProgram[j++] = pBuf[i];
			} break;
		}
	}

	// Assure null-termination
	pProgram[RealLength] = 0;

	return pProgram;
}

typedef struct
{
	int Position;
	const char *pProgram;
	CKVMap **ppJumpTable;

	unsigned char *pDataStart;
	unsigned char *pData;
	unsigned char *pDataEnd;

	size_t DataSize;
	size_t DataAllocSize;
} CBrainfuckContext;

void BrainfuckContext_Init(CBrainfuckContext *pContext, const char *pProgram, CKVMap **ppJumpTable)
{
	memset(pContext, 0, sizeof(CBrainfuckContext));
	pContext->DataAllocSize = 1024;
	pContext->pProgram = pProgram;
	pContext->ppJumpTable = ppJumpTable;

	pContext->pDataStart = malloc(pContext->DataAllocSize);
	pContext->DataSize = pContext->DataAllocSize;
	pContext->pData = pContext->pDataStart;
	pContext->pDataEnd = pContext->pDataStart + pContext->DataAllocSize;
	memset(pContext->pData, 0, pContext->DataSize);

	if(!pContext->pData)
		ERROR(2, "out of memory\n");
}

int RunBrainfuck(CBrainfuckContext *pContext)
{
	// gcc can't into optimizing >_>
	int Position = pContext->Position;
	const char *pProgram = pContext->pProgram;
	CKVMap **ppJumpTable = pContext->ppJumpTable;
	unsigned char *pDataStart = pContext->pDataStart;
	unsigned char *pData = pContext->pData;
	unsigned char *pDataEnd = pContext->pDataEnd;

	/* Optimization:
	 * Don't put any code after the switch construct!!
	 * mandelbrot with code after switch -> 44.52s
	 * mandelbrot without code after switch -> 37.60s
	 * with boundary overflow check -> 41.68s
	 *
	 * Boundary check code is faster if duplicated
	 * goto would be a better solution but it's forbidden....
	*/
	while(pProgram[Position])
	{
		switch(pProgram[Position])
		{
			case '>':
			{
				pData++;

				// Boundary overflow check
				// Underflow not documented, therefore not implemented
				if(pData >= pDataEnd)
				{
					pContext->DataSize += pContext->DataAllocSize;
					unsigned char *pAlloc = realloc(pDataStart, pContext->DataSize);
					if(!pAlloc)
						ERROR(2, "out of memory\n");

					pData = pAlloc + (pData - pDataStart);
					pDataStart = pAlloc;
					pDataEnd = pDataStart + pContext->DataSize;
					memset(pData, 0, pDataEnd - pData);
				}

				Position++;
				break;
			}
			case '<':
			{
				pData--;

				// Boundary overflow check
				// Underflow not documented, therefore not implemented
				if(pData >= pDataEnd)
				{
					pContext->DataSize += pContext->DataAllocSize;
					unsigned char *pAlloc = realloc(pDataStart, pContext->DataSize);
					if(!pAlloc)
						ERROR(2, "out of memory\n");

					pData = pAlloc + (pData - pDataStart);
					pDataStart = pAlloc;
					pDataEnd = pDataStart + pContext->DataSize;
					memset(pData, 0, pDataEnd - pData);
				}

				Position++;
				break;
			}
			case '+':
			{
				(*pData)++;
				Position++;
				break;
			}
			case '-':
			{
				(*pData)--;
				Position++;
				break;
			}
			case '.':
			{
				putchar(*pData);
				Position++;
				break;
			}
			case ',':
			{
				*pData = (unsigned char)(getchar() & 0xFF);
				Position++;
				break;
			}
			case '[':
			{
				if(!*pData)
				{
					CKVMap *pSearch = KVMap_Search(ppJumpTable, Position);
					if(!pSearch)
						ERROR(3, "parsing of input failed\n");
					Position = pSearch->Value;
				}
				Position++;
				break;
			}
			case ']':
			{
				if(*pData)
				{
					CKVMap *pSearch = KVMap_Search(ppJumpTable, Position);
					if(!pSearch)
						ERROR(3, "parsing of input failed\n");
					Position = pSearch->Value;
				}
				Position++;
				break;
			}
		}
	}

	pContext->Position = Position;
	pContext->pDataStart = pDataStart;
	pContext->pData = pData;
	pContext->pDataEnd = pDataEnd;

	return 0;
}

int main(int argc, char *argv[])
{
	// Interactive mode
	if(argc == 1)
	{

	}
	// Execution mode
	else if(argc >= 3)
	{
		if(strcmp(argv[1], "-e"))
			ERROR(1, "usage: ./assa [-e brainfuck_filnename]\n");

		long int FileLength;
		char *pFileData;
		FileLength = LoadFile(argv[2], &pFileData);

		char *pProgram;
		CKVMap **ppKVMap;
		pProgram = CompileBrainfuck(pFileData, FileLength, &ppKVMap);

		free(pFileData);

		CBrainfuckContext Context;
		BrainfuckContext_Init(&Context, pProgram, ppKVMap);

		RunBrainfuck(&Context);

		free(pProgram);
		free(Context.pDataStart);
		KVMap_Destroy(&ppKVMap);
	}
	else
		ERROR(1, "usage: ./assa [-e brainfuck_filnename]\n");

	return 0;
}
