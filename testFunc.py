import subprocess
import sys


def testFuncExe(wrapper_exe_file, sample_exe_file , func_addr):
    my_cmd = [wrapper_exe_file, sample_exe_file, func_addr]
    p = subprocess.Popen(my_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = p.communicate()
    # print out
    return out


if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) < 3:
        exit(-1)
    wrapper_exe_file, sample_exe_file, func_addr = args[0], args[1], args[2]
    testFuncExe(wrapper_exe_file, sample_exe_file , func_addr)