#!Makefile
#
# --------------------------------------------------------
#
#    Makefile  2015/2/25
#
# --------------------------------------------------------
#

C_SOURCES = $(shell find . -name "*.cpp")
C_OBJECTS = $(patsubst %.c, %.o, $(C_SOURCES))

CC = g++

C_FLAGS = -c -g -Wall -Iinclude -lpcap -std=c++11

all: $(C_OBJECTS) 
	@echo 链接 ...
	$(CC) $(C_OBJECTS) -lpcap -o  capture

.c.o:
	@echo 编译代码文件 $< ...
	$(CC) $(C_FLAGS) $< -o $@

.PHONY:clean
clean:
	@echo 清理临时文件
	$(RM) $(C_OBJECTS)

