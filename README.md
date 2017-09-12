# FunctionScan
	find function boundary and recognize library function

# Usage

## To output ld.script : 
	ld --verbose >ld.script 
## Compile main.cpp getReload.cpp
	g++  -T ld.script  main.cpp getReload.cpp -o main -std=c++11 -fno-stack-protector -g 

## run main
	./main sampleBinary
## TODO
	use python to execute main , input sample executable and function address, output function name.
