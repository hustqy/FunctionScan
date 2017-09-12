#include "elfHeader.h"
#define handle_error(msg) \
        do { perror(msg); exit(EXIT_FAILURE); } while (0)

void * virus_map_base;
void * mapFile ( char * file_name  ) {
    char *addr;
    int fd; 
    struct stat sb; 

    fd = open(file_name, O_RDONLY);
    if (fd == -1) 
        handle_error("open");

    if (fstat(fd, &sb) == -1)           /* To obtain file size */
        handle_error("fstat");

    addr = (char *)  mmap(NULL, sb.st_size, PROT_READ , MAP_PRIVATE, fd, 0); 
    if (addr == MAP_FAILED)
        handle_error("mmap");

    return (void*)addr;           
}

char * mmapStatic( ) {
    char * addr ;
    ADDR fixedAddr = 0x8048000;

    addr = (char *)  mmap( (void*)fixedAddr, 4096 , PROT_READ | PROT_WRITE| PROT_EXEC , MAP_FIXED |MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (addr == MAP_FAILED)
        handle_error("mmap2");
    return addr;
}

void testStrcat (ADDR testFunc ) {
    const char * src = "hello world";
    char dest[32] = {'r','o','b','o','t',};
    char dest2[32] = {'r','o','b','o','t',};
    int pid = fork () ; 

    if ( pid == 0 ) {
        __asm ( 
                "pushal\n\t" 
                "pushl %0\n\t"
                "pushl %1\n\t"
                "call *%2\n\t"
                "popl %%edi\n\t"
                "popl %%esi\n\t"
                "popal\n\t"
                :
                :"S"(src),"D"(dest),"a"(testFunc)
                );
        char * realStr =  strcat ( dest2 , src  ) ;
        if ( strncmp ( dest2 , dest , 17) == 0)
            cout << "strcat" << endl;
        exit (1);
    }
    else {
        sleep (1);
    }
    

}
void testStrncat ( ADDR testFunc  ) {
    const char * src = "hello world";
    char dest[32] = {'r','o','b','o','t',};
    char dest2[32] = {'r','o','b','o','t',};
    int count = 5;
    int pid = fork () ; 
    if ( pid == 0 ) {
        __asm ( 
                "pushal\n\t" 
                "pushl %0\n\t"
                "pushl %1\n\t"
                "pushl %2\n\t"
                "call *%3\n\t"
                "popl %%edi\n\t"
                "popl %%esi\n\t"
                "popl %%ecx\n\t"
                "popal\n\t"
                :
                :"c"(count), "S"(src),"D"(dest), "a"(testFunc)
                );
        char * realStr =  strncat ( dest , src , 5 ) ;
        if ( strncmp ( dest2 , dest , 11)==0 && dest[11] == 0 )
            cout << "strncat" << endl;
        exit (1);
    }
    else {
        sleep (1);
    }
}
void testStrncpy ( ADDR testFunc ) {
    const char * src = "hello world";
    char dest[12] = {0};
    int count = 5;
    int pid = fork () ; 
    if ( pid == 0 ) {
        __asm ( 
                "pushal\n\t" 
                "pushl %0\n\t"
                "pushl %1\n\t"
                "pushl %2\n\t"
                "call *%3\n\t"
                "popl %%edi\n\t"
                "popl %%esi\n\t"
                "popl %%ecx\n\t"
                "popal\n\t"
                :
                :"c"(count), "S"(src),"D"(dest), "a"(testFunc)
                );
        if ( strncmp ( dest , src , 5 ) == 0 && dest[5] == 0)
            cout << "strncpy" << endl;
        exit (1);
    }
    else {
        sleep (1);
    }
}
void testStrcpy (ADDR testFunc ) {
    const char * src = "hello world";
    char dest[12] = {0};
    int pid = fork () ; 

    if ( pid == 0 ) {
        __asm ( 
                "pushal\n\t" 
                "pushl %0\n\t"
                "pushl %1\n\t"
                "call *%2\n\t"
                "popl %%edi\n\t"
                "popl %%esi\n\t"
                "popal\n\t"
                :
                :"S"(src),"D"(dest),"a"(testFunc)
              );
        if ( strncmp ( dest , src , 11 ) == 0)
            cout << "strcpy" << endl;
        exit (1);
    }
    else {
        sleep (1);
    }

}
void testMemset ( ADDR testFunc ) {
    const char * src = "hello world";
    char dest[12] = {0};
    strcpy (dest, src);
    int count = 6;
    int ch = 'a';
    int pid = fork () ; 
    if ( pid == 0 ) {
        __asm ( 
                "pushal\n\t" 
                "pushl %0\n\t"
                "pushl %1\n\t"
                "pushl %2\n\t"
                "call *%3\n\t"
                "popl %%edi\n\t"
                "popl %%ebx\n\t"
                "popl %%ecx\n\t"
                "popal\n\t"
                :
                :"c"(count), "b"(ch),"D"(dest), "a"(testFunc)
                );
        if ( strncmp ( dest , "aaaaaaworld" , 11) == 0 )
            cout << "memset" << endl;
        exit (1);
    }
    else {
        sleep (1);
    }
}
void testStrcmp(  ADDR testFunc ) {

    const char * src = "hello world";
    const char *dest = "hello world";
    const char *dest1 = "gello world";
    const char *dest2 = "iello world";
    int pid = fork () ; 
    int res =0, res1 = 0, res2 = 0;
    if ( pid == 0 ) {
        __asm ( 
                "pushal\n\t" 
                "pushl %1\n\t"
                "pushl %2\n\t"
                "call *%3\n\t"
                "mov %%eax,%0\n\t"
                "popl %%edi\n\t"
                "popl %%esi\n\t"
                "popal\n\t"
                :"=m" (res ) 
                :"S"(src),"D"(dest),"r"(testFunc)
              );
        __asm ( 
                "pushal\n\t" 
                "pushl %1\n\t"
                "pushl %2\n\t"
                "call *%3\n\t"
                "mov %%eax,%0\n\t"
                "popl %%edi\n\t"
                "popl %%esi\n\t"
                "popal\n\t"
                :"=m" (res1 ) 
                :"S"(src),"D"(dest1),"r"(testFunc)
              );
        __asm ( 
                "pushal\n\t" 
                "pushl %1\n\t"
                "pushl %2\n\t"
                "call *%3\n\t"
                "mov %%eax,%0\n\t"
                "popl %%edi\n\t"
                "popl %%esi\n\t"
                "popal\n\t"
                :"=m" (res2 ) 
                :"S"(src),"D"(dest2),"r"(testFunc)
              );
        if ( res == 0 && res1 <0 && res2 >0)
            cout << "strcmp" << endl;
        exit (1);
    }
    else {
        sleep (1);
    }
    

}
/*void testStrlen ( ADDR testFunc ) {
    const char * src = "hello world";
    int pid = fork () ;
    int res = 0;
    if ( pid == 0 ) {
        __asm ( 
                "pushal\n\t" 
                "pushl %1\n\t"
                "call *%2\n\t"
                "popl %%edx\n\t"
                "popal\n\t"
                :"=a"(res) 
                :"d"(src),"0"(testFunc)
                );  
        if ( res  == 11 ) 
            cout << "strlen" << endl;
        exit (1);
    }
    else {
        sleep (1);
    }
}*/
int main (int argc , char * argv[]) {

    if ( argc < 1 )
    {
        cout << "input testFileName " <<endl;
        return 0 ;
    }
    char * buffer = (char * )mapFile ( argv [1] ) ;
    //char * addr2 =    mmapStatic ();
    ADDR fixedAddr = 0x8048000;
    struct_elf elf_info ; 
    reload ( buffer , fixedAddr , elf_info ) ;
    /*elf_info.elf_type = "static";
    elf_info.elf_loadbase_addr = (ADDR)virus_map_base ;
    ADDR phvaddr = (ADDR)(elf_info.ehdr.e_phoff + elf_info.elf_loadbase_addr);
    int phentrysize = (int)(elf_info.ehdr.e_phentsize);
    int phnum = (int)(elf_info.ehdr.e_phnum);
    ADDR exec_entrypoint = (ADDR)(elf_info.ehdr.e_entry);
    
    DEBUG(cout<<"exec_entrypoint: "<<exec_entrypoint<<endl;)  
    //ADDR ld_baseaddr = (ADDR)(getauxval(AT_BASE));
    //ADDR top_of_initstack = initStack(phvaddr, phentrysize, phnum, exec_entrypoint, ld_baseaddr);
    //changeExecFlow(top_of_initstack, exec_entrypoint, virus_analyse_result);
    */
    ADDR StrcpyFunc = 0x805be50;
    ADDR StrcatFunc = 0x805b9c0;
    ADDR MemsetFunc = 0x805cfc0;
    ADDR StrcmpFunc = 0x805bdd0;
    //testStrcpy ( StrcpyFunc );

    //testStrcat ( StrcatFunc );
    //testStrcat ( StrcpyFunc );
    testMemset ( MemsetFunc );
    testStrcmp ( StrcmpFunc );
    return 0 ;
}
