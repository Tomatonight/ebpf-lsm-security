# 编译 BPF 程序
clang -O2 -target bpf -g   -c kernel/file.c  -o build/file.o
#clang -O2 -target bpf -g   -c kernel/net.c  -o build/net.o
clang -O2 -target bpf -g   -c kernel/process.c  -o build/process.o

clang -O2 -target bpf -g   -c kernel/header.c  -o build/header.o

clang -O2 -target bpf -g   -c kernel/net.c  -o build/net.o

#llvm-link build/file.bc build/process.bc -o build/combined.bc
bpftool gen object build/test.o build/file.o build/header.o build/net.o build/process.o 
#clang -O2 -target bpf -c  build/file.bc -o build/test.o

# 编译用户空间程序

g++ -o build/build user/main.cpp user/parse.cpp user/log.cpp -lbpf

sudo ./build/build
