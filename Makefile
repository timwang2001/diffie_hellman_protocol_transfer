CC = g++
FLAGS = -g -O -Wall

OBJ := 
TOPDIR := $(PWD)
CLIDIR := $(TOPDIR)/client
SERDIR := $(TOPDIR)/server
BIN := main

SUBDIR := client server
# OBJHEAD := $(TOPDIR)/add/add.h $(TOPDIR)/sub/sub.h  #声明所有的头文件
# OBJLINK := --std=c99 #声明编译时候需要的链接护着其他的选项

export CC TOPDIR OBJDIR BINDIR BIN OBJLINK OBJ

all:CHECKDIR $(SUBDIR)
CHECKDIR:
	mkdir -p $(CLIDIR) $(SERDIR)
$(SUBDIR):RUN
	make -C $@
RUN:
	
clean:
	rm -rf $(CLIDIR)/client $(SERDIR)/server