ifndef CROSS_COMPILER
# default compier
CC = gcc
else
CC = $(CROSS_COMPILER)
endif

CXX = g++

ifndef EXTRA_CPPFLAGS
EXTRA_CPPFLAGS=
endif

ifndef EXTRA_LDFLAGS
EXTRA_LDFLAGS=
endif

CPPFLAGS = $(EXTRA_CPPFLAGS) -DSLJIT_CONFIG_AUTO=1 -DSLJIT_CONFIG_LLVM=1 -Isljit_src $(shell llvm-config-3.6 --cflags)
CFLAGS = -O0 -g -Wall -Wno-unused-function
REGEX_CFLAGS = -fshort-wchar
LDFLAGS = $(EXTRA_LDFLAGS) $(shell llvm-config-3.6 --cxxflags --ldflags --libs --system-libs)
LD = g++

TARGET = sljit_test regex_test

BINDIR = bin
SRCDIR = sljit_src
TESTDIR = test_src
REGEXDIR = regex_src

SLJIT_HEADERS = $(SRCDIR)/sljitLir.h $(SRCDIR)/sljitConfig.h $(SRCDIR)/sljitConfigInternal.h

SLJIT_LIR_FILES = $(SRCDIR)/sljitLir.c $(SRCDIR)/sljitExecAllocator.c $(SRCDIR)/sljitUtils.c \
	$(SRCDIR)/sljitNativeARM_32.c $(SRCDIR)/sljitNativeARM_T2_32.c $(SRCDIR)/sljitNativeARM_64.c \
	$(SRCDIR)/sljitNativeMIPS_common.c $(SRCDIR)/sljitNativeMIPS_32.c $(SRCDIR)/sljitNativeMIPS_64.c \
	$(SRCDIR)/sljitNativePPC_common.c $(SRCDIR)/sljitNativePPC_32.c $(SRCDIR)/sljitNativePPC_64.c \
	$(SRCDIR)/sljitNativeSPARC_common.c $(SRCDIR)/sljitNativeSPARC_32.c \
	$(SRCDIR)/sljitNativeTILEGX_64.c \
	$(SRCDIR)/sljitNativeX86_common.c $(SRCDIR)/sljitNativeX86_32.c $(SRCDIR)/sljitNativeX86_64.c

all: $(BINDIR) $(TARGET)

$(BINDIR) :
	mkdir $(BINDIR)

$(BINDIR)/sljitLir.o : $(BINDIR) $(SLJIT_LIR_FILES) $(SLJIT_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(SRCDIR)/sljitLir.c

$(BINDIR)/LLVMCWrappers.o : $(BINDIR) $(SRCDIR)/LLVMCWrappers.cpp
	$(CXX) -Wall -O0 -g -std=c++11 $(CPPFLAGS) $(CFLAGS) -c -o $@ $(SRCDIR)/LLVMCWrappers.cpp

$(BINDIR)/sljitMain.o : $(TESTDIR)/sljitMain.c $(BINDIR) $(SLJIT_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(TESTDIR)/sljitMain.c

$(BINDIR)/sljitTest.o : $(TESTDIR)/sljitTest.c $(BINDIR) $(SLJIT_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $(TESTDIR)/sljitTest.c

$(BINDIR)/regexMain.o : $(REGEXDIR)/regexMain.c $(BINDIR) $(SLJIT_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REGEX_CFLAGS) -c -o $@ $(REGEXDIR)/regexMain.c

$(BINDIR)/regexJIT.o : $(REGEXDIR)/regexJIT.c $(BINDIR) $(SLJIT_HEADERS) $(REGEXDIR)/regexJIT.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(REGEX_CFLAGS) -c -o $@ $(REGEXDIR)/regexJIT.c

clean:
	rm -f $(BINDIR)/*.o $(BINDIR)/sljit_test $(BINDIR)/regex_test

sljit_test: $(BINDIR)/sljitMain.o $(BINDIR)/sljitTest.o $(BINDIR)/sljitLir.o $(BINDIR)/LLVMCWrappers.o
	$(LD) $(CFLAGS) $(BINDIR)/sljitMain.o $(BINDIR)/sljitTest.o $(BINDIR)/sljitLir.o $(BINDIR)/LLVMCWrappers.o -o $(BINDIR)/$@ $(LDFLAGS) -lm -lpthread

regex_test: $(BINDIR)/regexMain.o $(BINDIR)/regexJIT.o $(BINDIR)/sljitLir.o $(BINDIR)/LLVMCWrappers.o
	$(LD) $(CFLAGS) $(BINDIR)/regexMain.o $(BINDIR)/regexJIT.o $(BINDIR)/sljitLir.o $(BINDIR)/LLVMCWrappers.o -o $(BINDIR)/$@ $(LDFLAGS) -lm -lpthread