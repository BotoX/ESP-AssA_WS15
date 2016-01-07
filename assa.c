//-----------------------------------------------------------------------------
// assa.c
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
  uint32_t *p_data_;
  size_t size_;
  size_t alloc_size_;
} CStack;

typedef struct
{
  uint32_t position_;
  char *p_program_;
  size_t program_size_;

  uint32_t *p_jump_table_;

  uint32_t *p_break_points_;
  size_t break_points_size_;
  char *p_break_points_backup_;

  unsigned char *p_data_start_;
  unsigned char *p_data_;
  size_t data_size_;
  size_t data_alloc_size_;
} CBrainfuckContext;

typedef int (*pfnCommand)(CBrainfuckContext *p_context, int argc, char *argv[]);
typedef struct
{
  const char *p_cmd_;
  pfnCommand pfn_cmd_;
} CCommand;

// Function prototypes
//-----------------------------------------------------------------------------
///
/// Prints an error message to stdout and exits depending on initialization.
/// First call to function is initialization, Error code represents mode.
///
/// @param error Error code / return code.
/// @param p_message Error message.
///
/// @return void
//
void error(int error, const char *p_message);

//-----------------------------------------------------------------------------
///
/// Allocate or grow memory for a stack.
///
/// @param p_stack Pointer to CStack object.
/// @param size size to allocate.
///
/// @return void
//
void stackAlloc(CStack *p_stack, size_t size);

//-----------------------------------------------------------------------------
///
/// Create a new stack.
///
/// @param p_stack Pointer to CStack object.
/// @param start_size size to initially allocate.
///
/// @return void
//
void stackInit(CStack *p_stack, size_t start_size);

//-----------------------------------------------------------------------------
///
/// Destroy a given stack.
///
/// @param p_stack Pointer to CStack object.
///
/// @return void
//
void stackDestroy(CStack *p_stack);

//-----------------------------------------------------------------------------
///
/// Push Element onto stack.
///
/// @param p_stack Pointer to CStack object.
/// @param Element Element to push onto stack.
///
/// @return void
//
void stackPush(CStack *p_stack, uint32_t element);

//-----------------------------------------------------------------------------
///
/// Pop Element from stack.
///
/// @param p_stack Pointer to CStack object.
///
/// @return The Element pop'd or UINT32_MAX if the stack is empty.
//
uint32_t stackPop(CStack *p_stack);

int cmdLoad(CBrainfuckContext *p_context, int argc, char **argv);
int cmdRun(CBrainfuckContext *p_context, int argc, char **argv);
int cmdEval(CBrainfuckContext *p_context, int argc, char **argv);
int cmdBreak(CBrainfuckContext *p_context, int argc, char **argv);
int cmdStep(CBrainfuckContext *p_context, int argc, char **argv);
int cmdMemory(CBrainfuckContext *p_context, int argc, char **argv);
int cmdShow(CBrainfuckContext *p_context, int argc, char **argv);
int cmdChange(CBrainfuckContext *p_context, int argc, char **argv);
int cmdQuit(CBrainfuckContext *p_context, int argc, char **argv);

//-----------------------------------------------------------------------------
///
/// Parses and executes a command line command.
///
/// @param p_context Pointer to CBrainfuckContext object.
/// @param p_command Pointer to first CCommand object in a null-terminated array.
/// @param p_line String to evaluate.
///
/// @return Returnvalue of executed command or -1 if none is found.
//
int commandLine(CBrainfuckContext *p_context, CCommand *p_command, char *p_line);

//-----------------------------------------------------------------------------
///
/// Filters junk out of brainfuck code.
///
/// @param p_data The string containing brainfuck code.
/// @param size Size of p_data.
/// @param pp_program Pointer to string which will hold the filtered code.
///
/// @return Size of pp_program.
//
size_t filterProgram(const char *p_data, size_t size, char **pp_program);

//-----------------------------------------------------------------------------
///
/// Loads a file into memory and filters invalid characters from it.
///
/// @param p_filename Path of the file.
/// @param pp_program Pointer to string which will hold the result.
///
/// @return Length of pp_program.
//
size_t loadProgram(const char *p_filename, char **pp_program);

//-----------------------------------------------------------------------------
///
/// Initializes a new CBrainfuckContext object.
///
/// @param p_context Pointer to CBrainfuckContext object.
/// @param p_program Brainfuck program string.
/// @param p_jump_table Brainfuck program jumptable.
///
/// @return void
//
void brainfuckContextInit(CBrainfuckContext *p_context, char *p_program, uint32_t *p_jump_table);

//-----------------------------------------------------------------------------
///
/// Initializes data memory for the CBrainfuckContext object.
///
/// @param p_context Pointer to CBrainfuckContext object.
///
/// @return void
//
void brainfuckContextInitData(CBrainfuckContext *p_context);

#ifdef BONUS
//-----------------------------------------------------------------------------
///
/// Segmentation fault signal handler.
///
/// @param signal Signal that invoked us (always SIGSEGV or not SIGSEGV for init).
/// @param p_signal Pointer to siginfo_t object.
/// @param p_arg Pointer to unkown object. On Linux ucontext_t.
///
/// @return void
//
static void sigsegvHandler(int signal, siginfo_t *p_signal, void *p_arg);

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
/// Jumps to instruction after brainfuck code invocation ((int(*)())p_binary)();
/// Pop stack once to get EIP (instruction pointer) of next instruction
/// where program returned because of a breakpoint.
/// Pop stack second time to get rid of previous EIP on stack.
/// Can use first pop'd EIP to jump back into brainfuck program afterwards.
///
/// @param p_buf Brainfuck program.
/// @param length Length of p_buf.
/// @param p_program_alloc_size Pointer to variable which will hold the size of
///              the compiled program.
///
/// @return Pointer to compiled program.
//
unsigned char *jitCompileBrainfuck(char *p_buf, size_t length, size_t *p_program_alloc_size);
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
/// @param p_buf Brainfuck program.
/// @param length Length of p_buf.
/// @param pp_jump_table Pointer to JumpTable which will hold the result.
///
/// @return non-zero on error
//
int buildJumpTable(char *p_buf, size_t length, uint32_t **pp_jump_table);

//-----------------------------------------------------------------------------
///
/// Runs a given CBrainfuckContext object.
///
/// @param p_context Pointer to CBrainfuckContext object.
/// @param steps Number of steps to execute or 0 to run the full program.
///
/// @return position of the instruction pointer.
//
uint32_t runBrainfuck(CBrainfuckContext *p_context, size_t steps);

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

void error(int error, const char *p_message)
{
  static char initializated = 0;
  // mode = 0 "-e" -> exit on error
  // mode = 1 -> interactive, only exit on errorcode 2
  static char mode = 0;
  if(!initializated)
  {
    initializated = 1;
    mode = error;
    return;
  }

  printf(p_message);

  if(!mode || error == 2)
    exit(error);
}

#ifdef BONUS
  static void sigsegvHandler(int signal, siginfo_t *p_signal, void *p_arg)
  {
    // Hack to avoid global vars
    static unsigned char **pp_data_start = 0;
    static size_t *p_data_alloc_size = 0;
    if(signal != SIGSEGV)
    {
      pp_data_start = (unsigned char **)p_signal;
      p_data_alloc_size = (size_t *)p_arg;
      return;
    }

    // previous execution context
    ucontext_t *p_context = p_arg;

    // edx register from crashed execution context is the current p_data pointer
    unsigned char *p_data = (unsigned char *)p_context->uc_mcontext.gregs[REG_EDX];

    // calc offset using p_data_start
    size_t data_offset = p_data - *pp_data_start;

    // reset locked memory page protection
    mprotect(*pp_data_start, *p_data_alloc_size + MEMPAGESIZE, PROT_READ | PROT_WRITE);

    // allocate another memory page for data
    void *p_alloc = mremap(*pp_data_start, *p_data_alloc_size, *p_data_alloc_size + MEMPAGESIZE, MREMAP_MAYMOVE);
    if(p_alloc == MAP_FAILED) // this could be anything, need to check errno...
      error(2, "[ERR] out of memory\n");

    // fix variables in main
    *p_data_alloc_size += MEMPAGESIZE;
    *pp_data_start = p_alloc;

    // lock next memory page again so we can catch the next invalid memory access
    mprotect(*pp_data_start - (*p_data_alloc_size + MEMPAGESIZE), MEMPAGESIZE, PROT_NONE);

    // calculate correct data pointer in new memory region (since it could've moved)
    p_data = *pp_data_start + data_offset;

    // put new data pointer into edx register
    p_context->uc_mcontext.gregs[REG_EDX] = (uintptr_t)p_data;

    // restore execution at failed instruction, yay \o/
    setcontext(p_context);
  }
#endif


/* CStack */
void stackAlloc(CStack *p_stack, size_t size)
{
  if(p_stack->alloc_size_ == 0)
  {
    p_stack->alloc_size_ = size;
    p_stack->p_data_ = malloc(p_stack->alloc_size_ * sizeof(uint32_t));
    if(!p_stack->p_data_)
      error(2, "[ERR] out of memory\n");
  }
  else
  {
    p_stack->alloc_size_ += size;
    void *p_alloc = realloc(p_stack->p_data_, p_stack->alloc_size_ * sizeof(uint32_t));
    if(!p_stack->p_data_)
    {
      free(p_stack->p_data_);
      error(2, "[ERR] out of memory\n");
    }
    p_stack->p_data_ = p_alloc;
  }
}

void stackInit(CStack *p_stack, size_t start_size)
{
  p_stack->size_ = 0;
  p_stack->alloc_size_ = 0;
  if(start_size)
    stackAlloc(p_stack, start_size);
}

void stackDestroy(CStack *p_stack)
{
  p_stack->size_ = 0;
  p_stack->alloc_size_ = 0;
  free(p_stack->p_data_);
}

void stackPush(CStack *p_stack, uint32_t element)
{
  if(p_stack->size_ >= p_stack->alloc_size_)
    stackAlloc(p_stack, 32);

  p_stack->p_data_[p_stack->size_++] = element;
}

uint32_t stackPop(CStack *p_stack)
{
  if(p_stack->size_ == 0)
    return UINT32_MAX;

  return p_stack->p_data_[--p_stack->size_];
}
/* CStack */

/* Console */
int cmdLoad(CBrainfuckContext *p_context, int argc, char **argv)
{
  if(argc < 2)
  {
    printf("[ERR] wrong parameter count\n");
    return 1;
  }

  if(p_context->p_program_)
  {
    free(p_context->p_program_);
    p_context->p_program_ = 0;
    p_context->position_ = 0;

    free(p_context->p_jump_table_);
    p_context->p_jump_table_ = 0;

    if(p_context->p_break_points_)
    {
      free(p_context->p_break_points_);
      p_context->p_break_points_ = 0;

      if(p_context->p_break_points_backup_)
      {
        free(p_context->p_break_points_backup_);
        p_context->p_break_points_backup_ = 0;
      }
    }
  }

  if(p_context->p_data_)
  {
    free(p_context->p_data_start_);
    p_context->p_data_ = 0;
    p_context->p_data_start_ = 0;
    p_context->data_size_ = 0;
  }

  p_context->program_size_ = loadProgram(argv[1], &p_context->p_program_);
  if(!p_context->program_size_)
    return 1;

  if(buildJumpTable(p_context->p_program_, p_context->program_size_, &p_context->p_jump_table_))
  {
    free(p_context->p_program_);
    p_context->p_program_ = 0;
    return 1;
  }

  return 0;
}

int cmdRun(CBrainfuckContext *p_context, int argc, char **argv)
{
  if(!p_context->p_program_)
  {
    printf("[ERR] no program loaded\n");
    return 1;
  }

  size_t steps = 0;
  if(argc == -1)
    steps = *((size_t *)argv);

  if(!p_context->p_data_)
    brainfuckContextInitData(p_context);

  if(p_context->p_break_points_)
  {
    size_t i;
    if(!p_context->p_break_points_backup_)
    {
      // Create array for storing original instructions
      p_context->p_break_points_backup_ = malloc(p_context->break_points_size_);
      if(!p_context->p_break_points_backup_)
        error(2, "[ERR] out of memory\n");

      for(i = 0; i < p_context->break_points_size_; i++)
      {
        // Ignore breakpoints which have already been passed
        if(p_context->p_break_points_[i] == UINT32_MAX)
          continue;

        // Position of breakpoint in p_program_
        uint32_t position = p_context->p_break_points_[i];

        // Save original instruction ...
        p_context->p_break_points_backup_[i] = p_context->p_program_[position];
        // ... and overwrite with 0, causing RunBrainfuck to return at <position>
        p_context->p_program_[position] = 0;
      }
    }

    uint32_t return_code = runBrainfuck(p_context, steps);

    // Program ended
    if(return_code == p_context->program_size_)
    {
      // Restore original program (in case we didn't hit a breakpoint we've set)
      for(i = 0; i < p_context->break_points_size_; i++)
      {
        if(p_context->p_break_points_[i] == UINT32_MAX)
          continue;

        uint32_t position = p_context->p_break_points_[i];

        p_context->p_program_[position] = p_context->p_break_points_backup_[i];
      }

      free(p_context->p_break_points_);
      p_context->p_break_points_ = 0;

      free(p_context->p_break_points_backup_);
      p_context->p_break_points_backup_ = 0;
    }
    else if(return_code == UINT32_MAX) // Stopped because of step
    {
    	return 0;
    }
    else // Stopped at breakpoint
    {
      uint32_t break_point = 0;
      for(i = 0; i < p_context->break_points_size_; i++)
      {
        // Find the p_break_points_ array index which made our program return ...
        if(p_context->p_break_points_[i] == return_code)
        {
          break_point = i;
          break;
        }
      }

      // ... and restore the original instruction
      p_context->p_program_[return_code] = p_context->p_break_points_backup_[break_point];
      // Delete breakpoint so we don't use it again
      p_context->p_break_points_[break_point] = UINT32_MAX;

      return 0;
    }
  }
  else
  {
    // Stopped early because of step, don't free program
    if(runBrainfuck(p_context, steps) == UINT32_MAX)
      return 0;
  }

  free(p_context->p_program_);
  p_context->p_program_ = 0;
  p_context->position_ = 0;

  free(p_context->p_jump_table_);
  p_context->p_jump_table_ = 0;

  return 0;
}

int cmdEval(CBrainfuckContext *p_context, int argc, char **argv)
{
  if(argc < 2)
  {
    printf("[ERR] wrong parameter count\n");
    return 1;
  }

  if(!p_context->p_data_)
    brainfuckContextInitData(p_context);

  // Store original context
  CBrainfuckContext old_context;
  memcpy(&old_context, p_context, sizeof(CBrainfuckContext));

  // load new program
  p_context->program_size_ = filterProgram(argv[1], strlen(argv[1]), &p_context->p_program_);
  p_context->position_ = 0;
  p_context->p_jump_table_ = 0;

  buildJumpTable(p_context->p_program_, p_context->program_size_, &p_context->p_jump_table_);
  runBrainfuck(p_context, 0);

  // Clean up
  free(p_context->p_program_);
  free(p_context->p_jump_table_);

  // Keep data pointer position?
  old_context.p_data_ = p_context->p_data_;

  // This could've changed
  old_context.data_size_ = p_context->data_size_;

  // Restore original context
  memcpy(p_context, &old_context, sizeof(CBrainfuckContext));

  return 0;
}

int cmdBreak(CBrainfuckContext *p_context, int argc, char **argv)
{
  if(!p_context->p_program_)
  {
    printf("[ERR] no program loaded\n");
    return 1;
  }

  if(argc < 2)
  {
    printf("[ERR] wrong parameter count\n");
    return 1;
  }

  long int temp = strtol(argv[1], 0, 10);
  if(temp < 0 || temp > p_context->program_size_)
    return 1;

  uint32_t break_point = temp;
  if(!p_context->p_break_points_)
  {
    p_context->break_points_size_ = 1;
    p_context->p_break_points_ = malloc(p_context->break_points_size_ * sizeof(uint32_t));
    if(!p_context->p_break_points_)
      error(2, "[ERR] out of memory\n");
  }
  else
  {
    // Avoid duplicate breakpoints
    size_t i;
    for(i = 0; i < p_context->break_points_size_; i++)
    {
      if(p_context->p_break_points_[i] == break_point)
        return 1;
    }

    if(p_context->p_break_points_backup_)
    {
      // Restore original program first
      for(i = 0; i < p_context->break_points_size_; i++)
      {
        if(p_context->p_break_points_[i] == UINT32_MAX)
          continue;

        uint32_t position = p_context->p_break_points_[i];

        p_context->p_program_[position] = p_context->p_break_points_backup_[i];
      }

      // reset p_break_points_backup_ so CMD_run builds it again and etc.
      free(p_context->p_break_points_backup_);
      p_context->p_break_points_backup_ = 0;
    }

    // Allocate memory for new breakpoint
    p_context->break_points_size_ += 1;
    void *p_alloc = realloc(p_context->p_break_points_, p_context->break_points_size_ * sizeof(uint32_t));
    if(!p_alloc)
      error(2, "[ERR] out of memory\n");

    p_context->p_break_points_ = p_alloc;
  }

  p_context->p_break_points_[p_context->break_points_size_ - 1] = break_point;

  return 0;
}

int cmdStep(CBrainfuckContext *p_context, int argc, char **argv)
{
  if(!p_context->p_program_)
  {
    printf("[ERR] no program loaded\n");
    return 1;
  }

  uint32_t steps = 1;
  if(argc >= 2)
  {
    long int temp = strtol(argv[1], 0, 10);
    if(temp <= 0)
      return 1;

    if(temp >= p_context->program_size_)
      return cmdRun(p_context, 0, 0);

    steps = temp;
  }

  return cmdRun(p_context, -1, (void *)&steps);
}

int cmdMemory(CBrainfuckContext *p_context, int argc, char **argv)
{
  if(!p_context->p_data_)
  {
    printf("[ERR] no program loaded\n");
    return 1;
  }

  int position = p_context->p_data_ - p_context->p_data_start_;
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
    char *p_next;
    int temp = strtol(argv[1], &p_next, 10);

    // Not a numerical input, asume type (convenience)
    if(p_next == argv[1] || *p_next != 0)
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
      if(temp < 0 || temp >= p_context->data_size_)
        return 1;

      position = temp;
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

  unsigned char *p_data = p_context->p_data_start_ + position;
  switch(Type)
  {
    case TYPE_HEX:
    {
      printf("Hex at %d: %x\n", position, *p_data);
    } break;
    case TYPE_INT:
    {
      printf("Integer at %d: %d\n", position, *p_data);
    } break;
    case TYPE_BIN:
    {
      char a_buf[16];
      char *p_buf = a_buf;

      size_t i;
      for(i = 128; i > 0; i >>= 1)
        *(p_buf++) = ((*p_data & i) == i) ? '1' : '0';
      *p_buf = 0;

      printf("Binary at %d: %s\n", position, a_buf);
    } break;
    case TYPE_CHAR:
    {
      printf("Char at %d: %c\n", position, *p_data);
    } break;
  }

  return 0;
}

int cmdShow(CBrainfuckContext *p_context, int argc, char **argv)
{
  if(!p_context->p_program_)
  {
    printf("[ERR] no program loaded\n");
    return 1;
  }

  size_t size = 10;
  if(argc >= 2)
  {
    long int temp = strtol(argv[1], 0, 10);
    if(temp <= 0)
      return 1;
    size = temp;
  }

  size_t i;
  // Restore original program first
  for(i = 0; i < p_context->break_points_size_; i++)
  {
    if(p_context->p_break_points_[i] == UINT32_MAX)
      continue;

    uint32_t position = p_context->p_break_points_[i];

    p_context->p_program_[position] = p_context->p_break_points_backup_[i];
  }

  // Print <size> amount of characters
  printf("%.*s\n", (int)size, &p_context->p_program_[p_context->position_]);

  // Restore breakpoints again
  for(i = 0; i < p_context->break_points_size_; i++)
  {
    if(p_context->p_break_points_[i] == UINT32_MAX)
      continue;

    uint32_t position = p_context->p_break_points_[i];

    p_context->p_program_[position] = 0;
  }

  return 0;
}

int cmdChange(CBrainfuckContext *p_context, int argc, char **argv)
{
  if(!p_context->p_data_)
  {
    printf("[ERR] no program loaded\n");
    return 1;
  }

  int position = p_context->p_data_ - p_context->p_data_start_;
  unsigned char value = 0x00;

  if(argc >= 2)
    position = strtol(argv[1], 0, 10);

  if(argc >= 3)
    value = strtol(argv[2], 0, 16);

  if(position < 0 || position > p_context->data_size_)
    return 1;

  unsigned char *p_data = p_context->p_data_start_ + position;

  *p_data = value;

  return 0;
}

int cmdQuit(CBrainfuckContext *p_context, int argc, char **argv)
{
  if(p_context->p_program_)
    free(p_context->p_program_);
  if(p_context->p_data_start_)
    free(p_context->p_data_start_);
  if(p_context->p_jump_table_)
    free(p_context->p_jump_table_);
  if(p_context->p_break_points_)
    free(p_context->p_break_points_);

  if(argc)
    printf("Bye.\n");
  exit(0);
}

int commandLine(CBrainfuckContext *p_context, CCommand *p_command, char *p_line)
{
  char *ap_argv[16] = {0};
  int argc = 0;
  char found = 1;
  char in_string = 0;

  while(*p_line)
  {
    if(*p_line == '"' && *(p_line - 1) != '\\')
    {
      *p_line = 0;
      in_string ^= 1;
      if(in_string)
      {
        p_line++;
        found = 1;
      }
    }

    if((*p_line == ' ' || *p_line == '\t') && !in_string)
    {
      *p_line = 0;
      found = 1;
    }
    else if(found)
    {
      if(argc < sizeof(ap_argv)/sizeof(*ap_argv))
      {
        ap_argv[argc++] = p_line;
        found = 0;
      }
      else // ignore additional parameters
        break;
    }
    p_line++;
  }

  if(argc)
  {
    while(p_command->p_cmd_)
    {
      if(!strcasecmp(ap_argv[0], p_command->p_cmd_))
        return p_command->pfn_cmd_(p_context, argc, ap_argv);

      p_command++;
    }
  }

  return -1;
}
/* Console */

size_t filterProgram(const char *p_data, size_t size, char **pp_program)
{
  // Count valid brainfuck characters
  size_t real_length = 0;
  size_t i;
  for(i = 0; i < size; i++)
  {
    switch(p_data[i])
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
        real_length++;
      } break;
    }
  }

  // Allocate memory for the filtered code
  char *p_program = malloc(real_length + 1);
  if(!p_program)
    error(2, "[ERR] out of memory\n");

  // And copy only the valid characters
  size_t j;
  for(i = 0, j = 0; i < size; i++)
  {
    switch(p_data[i])
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
        p_program[j++] = p_data[i];
      } break;
    }
  }

  // Assure null-termination
  p_program[real_length] = 0;

  *pp_program = p_program;

  return real_length;
}

size_t loadProgram(const char *p_filename, char **pp_program)
{
  char *p_file_data;
  FILE *p_file;
  p_file = fopen(p_filename, "rb");
  if(!p_file)
  {
    error(4, "[ERR] reading the file failed\n");
    return 0;
  }

  size_t file_size;
  fseek(p_file, 0, SEEK_END);
  file_size = ftell(p_file);
  fseek(p_file, 0, SEEK_SET);

  p_file_data = malloc(file_size + 1);
  if(!p_file_data)
    error(2, "[ERR] out of memory\n");

  fread(p_file_data, 1, file_size, p_file),
  fclose(p_file);

  // Assure null-termination
  p_file_data[file_size] = 0;

  size_t real_length = filterProgram(p_file_data, file_size, pp_program);

  free(p_file_data);

  return real_length;
}

void brainfuckContextInit(CBrainfuckContext *p_context, char *p_program, uint32_t *p_jump_table)
{
  memset(p_context, 0, sizeof(CBrainfuckContext));
  p_context->p_program_ = p_program;

  p_context->p_data_ = 0;
  p_context->p_data_start_ = 0;
  p_context->data_alloc_size_ = 1024;
  p_context->data_size_ = 0;

  p_context->p_jump_table_ = p_jump_table;
  p_context->p_break_points_ = 0;
  p_context->break_points_size_ = 0;
  p_context->p_break_points_backup_ = 0;
}

void brainfuckContextInitData(CBrainfuckContext *p_context)
{
  p_context->p_data_start_ = malloc(p_context->data_alloc_size_);
  p_context->data_size_ = p_context->data_alloc_size_;
  p_context->p_data_ = p_context->p_data_start_;
  memset(p_context->p_data_, 0, p_context->data_size_);

  if(!p_context->p_data_)
    error(2, "[ERR] out of memory\n");
}

#ifdef BONUS
unsigned char *jitCompileBrainfuck(char *p_buf, size_t length, size_t *p_program_alloc_size)
{
  CStack stack;
  CStack *p_stack = &stack;
  stackInit(p_stack, 32);

  unsigned char a_inst_p_data_add[] = {
    // add  edx, 1
    0x81, 0xC2, 0x01, 0x00, 0x00, 0x00
  };
  unsigned char a_inst_p_data_sub[] = {
    // sub  edx, 1
    0x81, 0xEA, 0x01, 0x00, 0x00, 0x00
  };
  unsigned char a_inst_data_add[] = {
    // add  BYTE PTR [edx], 1
    0x80, 0x02, 0x01
  };
  unsigned char a_inst_data_sub[] = {
    // sub  BYTE PTR [edx], 1
    0x80, 0x2A, 0x01
  };
  unsigned char a_inst_data_null[] = {
    // mov  BYTE PTR [edx], 0
    0xC6, 0x02, 0x00
  };
  unsigned char a_inst_print_data[] = {
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
  unsigned char a_inst_jump[] = {
    // jmp  <relative addr>
    0xE9, 0x00, 0x00, 0x00, 0x00
  };
  unsigned char a_inst_cond_jump[] = {
    // cmp  BYTE PTR [edx], 0
    0x80, 0x3A, 0x00,
    // jne
    0x0F, 0x85, 0x00, 0x00, 0x00, 0x00
  };
  unsigned char a_inst_return_normal[] = {
    // mov  eax, 0 ; return with 0
    0xB8, 0x00, 0x00, 0x00, 0x00,
    // retn
    0xC3
  };

  size_t program_size = 0;
  // Align to memory page
  size_t program_alloc_size = (length + MEMPAGESIZE) & MEMPAGEMASK;

  unsigned char *p_program = mmap(0, program_alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(p_program == MAP_FAILED)
    error(2, "[ERR] out of memory\n");

  // translate into x86 instructions and optimize
  size_t i;
  for(i = 0; i < length; i++)
  {
    switch(p_buf[i])
    {
      case '>':
      {
        if(p_buf[i - 1] == '>')
          p_program[program_size - 4] += 1;
        else
        {
          memcpy(&p_program[program_size], a_inst_p_data_add, sizeof(a_inst_p_data_add));
          program_size += sizeof(a_inst_p_data_add);
        }
      } break;
      case '<':
      {
        if(p_buf[i - 1] == '<')
          p_program[program_size - 4] += 1;
        else
        {
          memcpy(&p_program[program_size], a_inst_p_data_sub, sizeof(a_inst_p_data_sub));
          program_size += sizeof(a_inst_p_data_sub);
        }
      } break;
      case '+':
      {
        if(p_buf[i - 1] == '+')
          p_program[program_size - 1] += 1;
        else
        {
          memcpy(&p_program[program_size], a_inst_data_add, sizeof(a_inst_data_add));
          program_size += sizeof(a_inst_data_add);
        }
      } break;
      case '-':
      {
        if(p_buf[i - 1] == '-')
          p_program[program_size - 1] += 1;
        else
        {
          memcpy(&p_program[program_size], a_inst_data_sub, sizeof(a_inst_data_sub));
          program_size += sizeof(a_inst_data_sub);
        }
      } break;
      case '.':
      {
        memcpy(&p_program[program_size], a_inst_print_data, sizeof(a_inst_print_data));
        program_size += sizeof(a_inst_print_data);
      } break;
      case ',':
      {
        // not implemented - who uses this anyways
      } break;
      case '[':
      {
        if(p_buf[i + 1] == '-' && p_buf[i + 2] == ']')
        {
          memcpy(&p_program[program_size], a_inst_data_null, sizeof(a_inst_data_null));
          program_size += sizeof(a_inst_data_null);
          i += 2;
        }
        else
        {
          memcpy(&p_program[program_size], a_inst_jump, sizeof(a_inst_jump));
          program_size += sizeof(a_inst_jump);

          // relative jump to the next instruction
          stackPush(p_stack, program_size);
        }
      } break;
      case ']':
      {
        size_t jump = stackPop(p_stack);
        if(jump == SIZE_MAX)
          error(3, "[ERR] parsing of input failed\n");

        memcpy(&p_program[program_size], a_inst_cond_jump, sizeof(a_inst_cond_jump));

        uint32_t relative_jmp_addr;

        // jump to ']' from '['
        relative_jmp_addr = program_size - jump;
        memcpy(&p_program[jump - 4], &relative_jmp_addr, 4);

        program_size += sizeof(a_inst_cond_jump);

        // conditional jump back to '[' from ']'
        relative_jmp_addr = program_size - jump;
        relative_jmp_addr *= -1;
        memcpy(&p_program[program_size - 4], &relative_jmp_addr, 4);

      } break;
    }

    if(program_alloc_size - program_size <= sizeof(a_inst_print_data))
    {
      // This works because our jumps are relative
      void *p_alloc = mremap(p_program, program_alloc_size, program_alloc_size + MEMPAGESIZE, MREMAP_MAYMOVE);
      if(p_alloc == MAP_FAILED) // this could be anything, need to check errno...
        error(2, "[ERR] out of memory\n");

      program_alloc_size += MEMPAGESIZE;
      p_program = p_alloc;
    }
  }

  // '[' ']' derp
  if(stack.size_)
    error(3, "[ERR] parsing of input failed\n");

  stackDestroy(p_stack);

  // clean return
  memcpy(&p_program[program_size], a_inst_return_normal, sizeof(a_inst_return_normal));
  program_size += sizeof(a_inst_return_normal);

  *p_program_alloc_size = program_alloc_size;

  // make executable
  mprotect(p_program, program_alloc_size, PROT_READ | PROT_EXEC);

  return p_program;
}
#endif

int buildJumpTable(char *p_buf, size_t length, uint32_t **pp_jump_table)
{
  CStack stack;
  CStack *p_stack = &stack;

  size_t open_bracket_size = 0;
  size_t closed_bracket_size = 0;
  size_t last_bracket = 0;

  // Count '[' and ']' in the program
  // Also remember the last ']' to make memory usage a bit better
  size_t i;
  for(i = 0; i < length; i++)
  {
    switch(p_buf[i])
    {
      case '[':
      {
        open_bracket_size++;
      } break;
      case ']':
      {
        closed_bracket_size++;
        last_bracket = i;
      } break;
    }
  }
  last_bracket++;

  if(open_bracket_size != closed_bracket_size)
  {
    error(3, "[ERR] parsing of input failed\n");
    return 1;
  }

  uint32_t *p_jump_table = malloc(last_bracket * sizeof(uint32_t));
  if(!p_jump_table)
    error(2, "[ERR] out of memory\n");

  memset(p_jump_table, 0, last_bracket * sizeof(uint32_t));

  stackInit(p_stack, 32);

  for(i = 0; i < length; i++)
  {
    switch(p_buf[i])
    {
      case '[':
      {
        // Push position of '[' onto stack
        // This will be pop'd later at the corresponding ']'
        stackPush(p_stack, i);
      } break;
      case ']':
      {
        uint32_t jump = stackPop(p_stack);

        // '[' jumps to previously push'd ']' position
        p_jump_table[i] = jump;
        // previously push'd '[' jumps to this ']'
        p_jump_table[jump] = i;
      } break;
    }
  }

  stackDestroy(p_stack);

  *pp_jump_table = p_jump_table;

  return 0;
}

// This is so horrible, I'm sorry :(((
// But duplicating code is forbidden, goto is forbidden
// I was left with no other choice D:
// (except sacrificing performance obv. :p)
#define MACRO_RUN_BRAINFUCK_FUNC() \
  switch(*p_program) \
  { \
    case '>': \
    { \
      p_data++; \
 \
      /* Boundary overflow check */ \
      if(p_data >= p_data_end) \
      { \
        p_context->data_size_ += p_context->data_alloc_size_; \
        void *p_alloc = realloc(p_context->p_data_start_, p_context->data_size_); \
        if(!p_alloc) \
          error(2, "[ERR] out of memory\n"); \
 \
        p_data = p_alloc + (p_data - p_context->p_data_start_); \
        p_context->p_data_start_ = p_alloc; \
        p_data_end = p_context->p_data_start_ + p_context->data_size_; \
        memset(p_data, 0, p_data_end - p_data); \
      } \
    } break; \
    case '<': \
    { \
      p_data--; \
      /* underflow ignored */ \
    } break; \
    case '+': \
    { \
      (*p_data)++; \
    } break; \
    case '-': \
    { \
      (*p_data)--; \
    } break; \
    case '.': \
    { \
      putchar(*p_data); \
    } break; \
    case ',': \
    { \
      *p_data = getchar(); \
    } break; \
    case '[': \
    { \
      if(!*p_data) \
        p_program = p_program_start + p_jump_table[p_program - p_program_start] - 1; \
    } break; \
    case ']': \
    { \
      if(*p_data) \
        p_program = p_program_start + p_jump_table[p_program - p_program_start] - 1; \
    } break; \
    default: \
    { \
      p_context->position_ = p_program - p_program_start; \
      p_context->p_data_ = p_data; \
 \
      return p_context->position_; \
    } break; \
  }

uint32_t runBrainfuck(CBrainfuckContext *p_context, size_t steps)
{
  // gcc can't into optimizing >_>
  register const char *p_program_start = p_context->p_program_;
  register const char *p_program = p_context->p_program_ + p_context->position_;
  register unsigned char *p_data = p_context->p_data_;
  register unsigned char *p_data_end = p_context->p_data_start_ + p_context->data_size_;
  register uint32_t *p_jump_table = p_context->p_jump_table_;

  if(!steps)
  {
    for(;; p_program++)
    {
      MACRO_RUN_BRAINFUCK_FUNC()
    }
  }
  else
  {
    for(; steps--; p_program++)
    {
      MACRO_RUN_BRAINFUCK_FUNC()
    }
    p_context->position_ = p_program - p_program_start;
    p_context->p_data_ = p_data;

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

    CCommand a_commands[] =
    {
      {"load",   cmdLoad},
      {"run",    cmdRun},
      {"eval",   cmdEval},
      {"break",  cmdBreak},
      {"step",   cmdStep},
      {"memory", cmdMemory},
      {"show",   cmdShow},
      {"change", cmdChange},
      {"quit",   cmdQuit},
      {0,        0}
    };

    CBrainfuckContext context;
    brainfuckContextInit(&context, 0, 0);

    while(1)
    {
      printf("esp> ");
      char a_buf[PATH_MAX + 16];
      size_t length;

      if(fgets(a_buf, sizeof(a_buf), stdin) == 0) // EOF
        cmdQuit(&context, 0, 0);

      length = strlen(a_buf) - 1;
      a_buf[length] = 0; // Eat trailing '\n'

      commandLine(&context, &a_commands[0], a_buf);
    }
  }
  // Execution mode
  else if(argc >= 3)
  {
    // Init error func to execution mode
    error(0, 0);

    if(strcmp(argv[1], "-e"))
      error(1, "[ERR] usage: ./assa [-e brainfuck_filnename]\n");

    char *p_program;
    size_t program_size;
    program_size = loadProgram(argv[2], &p_program);

#ifdef BONUS
    size_t data_alloc_size = MEMPAGESIZE + MEMPAGESIZE;
    unsigned char *p_data = mmap(0, data_alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(p_data == MAP_FAILED)
      error(2, "[ERR] out of memory\n");
    unsigned char *p_data_start = p_data;

    // Set up memory trap
    mprotect(p_data + (data_alloc_size - MEMPAGESIZE), MEMPAGESIZE, PROT_NONE);

    // install SIGSEGV trap
    // this is used to detect invalid memory access
    struct sigaction sig_action;
    memset(&sig_action, 0, sizeof(sig_action));
    sigemptyset(&sig_action.sa_mask);
    sig_action.sa_sigaction = sigsegvHandler;
    sig_action.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sig_action, NULL);

    // Hack to avoid global vars
    sigsegvHandler(-1, (void *)&p_data_start, (void *)&data_alloc_size);

    size_t binary_alloc_size;
    unsigned char *p_binary;
    p_binary = jitCompileBrainfuck(p_program, program_size, &binary_alloc_size);

    free(p_program);

    int ret;
    // mov  edx, [ebp+p_data]
    // ^ intel syntax
    // v gas syntax
    asm("mov %[p_data], %%edx"
        :: [p_data] "m" (p_data) : "edx");

    ret = ((int(*)())p_binary)();

    // mov  [ebp+p_data], edx ; Fix data pointer
    // ^ intel syntax
    // v gas syntax
    asm("mov %%edx, %[p_data]"
        : [p_data] "=r" (p_data) :: "edx");

    // suppress unused variable
    (void)ret;

    munmap(p_data_start, data_alloc_size);
    munmap(p_binary, binary_alloc_size);
#else
    uint32_t *p_jump_table;
    buildJumpTable(p_program, program_size, &p_jump_table);

    CBrainfuckContext context;
    brainfuckContextInit(&context, p_program, p_jump_table);
    brainfuckContextInitData(&context);

    runBrainfuck(&context, 0);

    free(p_program);
    free(context.p_data_start_);
    free(p_jump_table);
#endif
  }
  else
  {
    error(0, 0);
    error(1, "[ERR] usage: ./assa [-e brainfuck_filnename]\n");
  }

  return 0;
}
