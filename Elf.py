import struct
import logging
import sys
from capstone import *

class ELF_HDR:
    def __init__(self, option):
        self.__struct_format__ = '16s2HI3QI6H' if option == "64" else '16s2HI3II6H'

        self.e_ident = None
        self.e_type = None
        self.e_machine = None
        self.e_version = None
        self.e_entry = None
        self.e_phoff = None
        self.e_shoff = None
        self.e_flags = None
        self.e_ehsize = None
        self.e_phentsize = None
        self.e_phnum = None
        self.e_shentsize = None
        self.e_shnum = None
        self.e_shstrndx = None

        self.order_key_list = \
            [
                'e_ident',
                'e_type',
                'e_machine',
                'e_version',
                'e_entry',
                'e_phoff',
                'e_shoff',
                'e_flags',
                'e_ehsize',
                'e_phentsize',
                'e_phnum',
                'e_shentsize',
                'e_shnum',
                'e_shstrndx'
            ]

    def set_all_attr(self, value_list):
        if len(self.order_key_list) != len(value_list):
            print("Arguments error!")
            return None

        for (attr, value) in zip(self.order_key_list, value_list):
            setattr(self, attr, value)

        return self

    def get_all_attr(self):
        value_list = []
        for attr in self.order_key_list:
            value_list.append(getattr(self, attr))
        return value_list

    def judge_if_elf(self):
        if self.e_ident[:4] == "7f454c46".decode("hex"):
            return True
        else:
            return False

    def bit_width(self):
        if self.e_ident[4:5] == "01".decode("hex"):
            return "32"
        elif self.e_ident[4:5] == "02".decode("hex"):
            return "64"
        else:
            return None

    def big_or_little_endian(self):
        if self.e_ident[5:6] == "01".decode("hex"):
            return "little"
        elif self.e_ident[4:5] == "02".decode("hex"):
            return "big"
        else:
            return None

    def file_type(self):
        if self.e_type == 1:
            return "ET_REL"
        elif self.e_type == 2:
            return "ET_EXEC"
        elif self.e_type == 3:
            return "ET_DYN"
        else:
            return None

    def machine_arch(self):
        if self.e_machine == 0x3:
            return "x86"
        elif self.e_machine == 0x28:
            return "arm"
        elif self.e_machine == 0x3e:
            return "x64"
        elif self.e_machine == 0xb7:
            return "arm_64"
        else:
            return None


class ELF_SHDR:
    def __init__(self, option):
        self.sh_name = None
        self.sh_type = None
        self.sh_flag = None
        self.sh_addr = None
        self.sh_offset = None
        self.sh_size = None
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None
        self.sh_entsize = None

        self.order_key_list = \
            [
                'sh_name',
                'sh_type',
                'sh_flag',
                'sh_addr',
                'sh_offset',
                'sh_size',
                'sh_link',
                'sh_info',
                'sh_addralign',
                'sh_entsize'
            ]

        self.__struct_format__ = '10I' if option == '32' else '2I4Q2I2Q'

        self.name = None

    def set_all_attr(self, value_list):
        if len(self.order_key_list) != len(value_list):
            ERR("Arguments error!")
            return None

        for (attr, value) in zip(self.order_key_list, value_list):
            setattr(self, attr, value)

        return self

    def get_all_attr(self):
        value_list = []
        for attr in self.order_key_list:
            value_list.append(getattr(self, attr))
        return value_list

    def section_name(self, string_table):
        if self.name == None:
            binary_str = string_table[self.sh_name:].split('\0', 1)[0]
            self.name = struct.pack(str(len(binary_str))+'s', binary_str)
        return self.name

    def section_type(self):
        if self.sh_type == 0:
            return "NULL"
        elif self.sh_type == 1:
            return "PROGBITS"
        elif self.sh_type == 2:
            return "SYMTAB"
        elif self.sh_type == 3:
            return "STRTAB"
        else:
            return None

    def section_flags(self):
        flags_string = []
        if self.sh_flag & 1:
            flags_string.append("WRITE")
        if self.sh_flag & 2:
            flags_string.append("ALLOC")
        if self.sh_flag & 4:
            flags_string.append("EXEC")
        return flags_string

    def section_position(self):
        return (self.sh_offset, self.sh_size, self.sh_addr)

    def section_align(self):
        return 2 ** self.sh_addralign
class ELF_PHDR:
    def __init__(self, option):
        self.p_type = None
        self.p_offset = None
        self.p_vaddr = None
        self.p_paddr = None
        self.p_filesz = None
        self.p_memsz = None
        self.p_flags = None
        self.p_align = None

        self.order_key_list = \
            [
                'p_type',
                'p_offset',
                'p_vaddr',
                'p_paddr',
                'p_filesz',
                'p_memse',
                'p_flags',
                'p_align'
            ]

        self.__struct_format__ = '8I' if option == '32' else '2I6Q'


    def set_all_attr(self, value_list):
        for (attr, value) in zip(self.order_key_list, value_list):
            setattr(self, attr, value)
        return self

    def get_all_attr(self):
        value_list = []
        for attr in self.order_key_list:
            value_list.append(getattr(self, attr))
        return value_list

    def section_type(self):
        if self.p_type == 0:
            return "NULL"
        elif self.p_type == 1:
            return "LOAD"
        elif self.p_type == 2:
            return "DYNAMIC"
        elif self.p_type == 3:
            return "INTERP"
        else:
            return None

    def section_flags(self):
        flags_string = []
        if self.p_flags & 1:
            flags_string.append("EXEC")
        if self.p_flags & 2:
            flags_string.append("WRITE")
        if self.p_flags & 4:
            flags_string.append("READ")
        return flags_string

    def section_position(self):
        return (self.p_offset, self.p_filesz, self.p_vaddr)

    def section_align(self):
        return 2 ** self.p_align
class SYMBOL:
    def __init__(self, option):
        self.st_name = \
        self.st_value = \
        self.st_size = \
        self.st_info = \
        self.st_other = \
        self.st_shndx = None

        self.order_key_list = \
            [
                'st_name',
                'st_value',
                'st_size',
                'st_info',
                'st_other',
                'st_shndx',
            ]

        self.__struct_format__ = '3I2BH' if option == '32' else 'IQI2BH'
        self.name = None
        self.data = None

    def set_all_attr(self, value_list):
        for (attr, value) in zip(self.order_key_list, value_list):
            setattr(self, attr, value)
        return self

    def get_all_attr(self):
        value_list = []
        for attr in self.order_key_list:
            value_list.append(getattr(self, attr))
        return value_list

    def symbol_name(self, string_table):
        if self.name == None:
            binary_str = string_table[self.st_name:].split('\0', 1)[0]
            self.name = struct.pack(str(len(binary_str))+'s', binary_str)
        return self.name

    def judge_if_function(self):
        return True if (self.st_info & 15) == 2 else False

    def judge_if_offset(self):
        return False if self.st_shndx in [0xfff1, 0xfff2, 0] else True

class Elf_Parse:
    name_list = ["scanf", "__isoc99_scanf","printf", "gets", "puts", "getchar", "putchar", "getc", "putc",
                 "open","read", "write",
                 "alloc", "realloc", "free", "memcpy", "strcpy", "strncpy", "strlen", "strcat", "strcmp",
                 "strncmp", "memset", "strstr", "atoi"]

    def __init__(self, file_name, offset=0):
        with open(file_name, 'rb') as self.file_handle:
            self.binary = self.file_handle.read()
            elf_ident = struct.unpack('16s', self.binary[:16])[0]
            if elf_ident[:4] == "7f454c46".decode("hex"):
                option = '32' if elf_ident[4:5] == "01".decode("hex") else '64'
            else:
                logging.error("It's not an elf file!")
                sys.exit(-1)

        self.elf_hdr = ELF_HDR(option)
        self.elf_shdr_list = []
        self.elf_phdr_list = []
        self.arch = None
        self.offset = offset
        self.critical_function = []

    def parse_elf_header(self):
        value_list = struct.unpack(self.elf_hdr.__struct_format__, self.binary[:struct.calcsize(self.elf_hdr.__struct_format__)])
        self.elf_hdr.set_all_attr(value_list)
        self.arch = self.elf_hdr.machine_arch()

    def parse_elf_section_header(self):
        for i in range(self.elf_hdr.e_shnum):
            elf_shdr = ELF_SHDR(self.elf_hdr.bit_width())
            base = self.binary[self.elf_hdr.e_shoff + i * self.elf_hdr.e_shentsize:]
            value_list = struct.unpack(elf_shdr.__struct_format__, base[:struct.calcsize(elf_shdr.__struct_format__)])
            elf_shdr.set_all_attr(value_list)
            self.elf_shdr_list.append(elf_shdr)

        self.section_string_table = self.binary[(self.elf_shdr_list[self.elf_hdr.e_shstrndx].sh_offset):]

        for i in range(self.elf_hdr.e_shnum):
            self.elf_shdr_list[i].section_name(self.section_string_table)

    def parse_elf_program_header(self):
        for i in range(self.elf_hdr.e_phnum):
            elf_phdr = ELF_PHDR(self.elf_hdr.bit_width())
            base = self.binary[self.elf_hdr.e_phoff + i * self.elf_hdr.e_phentsize:]
            value_list = struct.unpack(elf_phdr.__struct_format__, base[:struct.calcsize(elf_phdr.__struct_format__)])
            elf_phdr.set_all_attr(value_list)
            self.elf_phdr_list.append(elf_phdr)


    def get_function_table(self):
        function_table = []
        base = size = 0
        for elf_shdr in self.elf_shdr_list:
            if elf_shdr.section_name(self.section_string_table) == '.symtab':
                base, size = elf_shdr.sh_offset, elf_shdr.sh_size
            elif elf_shdr.section_name(self.section_string_table) == '.strtab':
                self.symbol_string_table = self.binary[elf_shdr.sh_offset:elf_shdr.sh_offset + elf_shdr.sh_size]
            else:
                pass
        i = base
        while i < base + size:
            sym = SYMBOL(self.elf_hdr.bit_width())
            value_list = struct.unpack(sym.__struct_format__, self.binary[i:i + struct.calcsize(sym.__struct_format__)])
            sym.set_all_attr(value_list)
            if sym.judge_if_function() and sym.judge_if_offset():
                sym_name = sym.symbol_name(self.symbol_string_table)
                function_table.append((sym_name, hex(sym.st_value + self.offset)))
                if sym_name in Elf_Parse.name_list:
                    cur_text_section = self.elf_shdr_list[sym.st_shndx]
                    offset = cur_text_section.sh_offset + sym.st_value - cur_text_section.sh_addr
                    sym.data =  self.binary [offset : offset + sym.st_size]
                    self.critical_function.append(sym)
            i += struct.calcsize(sym.__struct_format__)

        print "after critical_function"
        for s in self.critical_function:
            print s.name , s.st_value, s.st_size
        #     print s.data
        return self.critical_function

    def get_main_address(self):
        entry = self.elf_hdr.e_entry
        for shr in self.elf_shdr_list[1:]:
            if shr.name == '.text' and 'EXEC' in shr.section_flags():
                return self.try_disasm(entry - shr.sh_addr + shr.sh_offset )


    def try_disasm(self, start_addr):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        pre = None
        for i in md.disasm(self.binary[start_addr:start_addr + 0x100] , 0x100):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            if i.mnemonic == u'call':
                break
            pre = i.op_str
        return pre

if __name__ == '__main__':
    args = sys.argv[1:]
    path = args[0]
    parser = Elf_Parse(path)
    parser.parse_elf_header()
    parser.parse_elf_section_header()
    parser.parse_elf_program_header()
    # parser.get_function_table()
    print parser.get_main_address()
    print "over"

