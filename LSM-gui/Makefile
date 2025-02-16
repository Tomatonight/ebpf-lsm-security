CC = clang
CXX = g++
CFLAGS = -O3 -target bpf -g
LDFLAGS = -lbpf
OBJ_DIR = build
SRC_DIR = kernel
USER_SRC_DIR = user

# BPF 相关的文件
BPF_FILES = file process header net 
USER_FILES = main parse log

# 编译目标
TARGET = $(OBJ_DIR)/build

# 默认目标
all: $(OBJ_DIR)/build $(OBJ_DIR)/test.o

# 编译 BPF 程序
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/header.h
	$(CC) $(CFLAGS) -c $< -o $@

# 编译用户空间程序
#$(OBJ_DIR)/build: $(USER_SRC_DIR)/main.cpp $(USER_SRC_DIR)/parse.cpp $(USER_SRC_DIR)/log.cpp 
#	$(CXX) -o $@ $^ $(LDFLAGS)

# 使用 bpftool 生成最终的 BPF 对象文件
$(OBJ_DIR)/test.o: $(OBJ_DIR)/file.o $(OBJ_DIR)/process.o $(OBJ_DIR)/header.o $(OBJ_DIR)/net.o
	bpftool gen object $(OBJ_DIR)/test.o $(OBJ_DIR)/file.o $(OBJ_DIR)/header.o $(OBJ_DIR)/net.o $(OBJ_DIR)/process.o

# 清理目标
clean:
	rm -rf $(OBJ_DIR)/*.o $(OBJ_DIR)/build

.PHONY: all clean
