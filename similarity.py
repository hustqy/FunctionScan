import  sys
from Elf import  *
import subprocess

def objdump(exe_file_name, objdump_file):
    my_cmd = ["objdump", "-d"]
    my_cmd.append(exe_file_name)
    file_out = open(objdump_file,'w+')
    proc = subprocess.call(my_cmd,stdout = file_out, stderr=subprocess.PIPE)

def com ( src ,dst):
    count = 0
    for item in src:
        if item in dst:
            count +=1
    return count*2.0 / ( len(src) + len(dst))

def w_shingle(string, w):
    """Return the set of contiguous sequences (shingles) of `w` words
    in `string`."""

    num_words = len(string)
    # Confirm that 0 < `w` <= `num_words`
    if w > num_words or w == 0:
        raise Exception('Invalid argument -w')
    # If w is equal to the number of words in the input string, the
    # only item in the set is `words`.
    return [string[i:i + w] for i in range(len(string) - w + 1)]


def similariy(data1 ,data2):
    words1 = w_shingle(data1,3)
    words2 = w_shingle(data2,3)
    return com(words1,words2)

MaxConfidence = 0.2


def main(input_path , template_file):
    with open(input_path , 'r') as f:
        input_binary = f.read()
    # input_binary = input_binary[:30]
    parser = Elf_Parse(template_file)
    parser.parse_elf_header()
    parser.parse_elf_section_header()
    parser.parse_elf_program_header()
    symlist = parser.get_function_table()
    similar = 0
    name = None
    for sym in symlist:
        cur_data= sym.data
        if len (cur_data ) > len(input_binary):
            cur_data = cur_data[:len(input_binary)]
        cur = similariy(input_binary, cur_data)
        print sym.name,cur
        if cur > similar:
            similar = cur
            name = sym.name
    if similar < MaxConfidence:
        return None
    else:
        return name

if __name__ == '__main__':
    args = sys.argv[1:]
    template_file = args[0]
    input_path = args[1]
    name = main(input_path , template_file)
    print name