/*
 *    Stack-less Just-In-Time compiler
 *
 *    Copyright 2009-2012 Alex Şuhan (alex.suhan@gmail.com). All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice, this list of
 *      conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright notice, this list
 *      of conditions and the following disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDER(S) OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _LLVM_CPP_WRAPPERS_H_
#define _LLVM_CPP_WRAPPERS_H_

#include <llvm-c/Core.h>

#ifdef __cplusplus
extern "C" {
#endif /* !defined(__cplusplus) */

LLVMValueRef LLVMBuildAddOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                  LLVMValueRef LHS, LLVMValueRef RHS,
                                  const char *Name, LLVMValueRef* overflow);

LLVMValueRef LLVMBuildSubOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                  LLVMValueRef LHS, LLVMValueRef RHS,
                                  const char *Name, LLVMValueRef* overflow);

LLVMValueRef LLVMBuildUSubOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                   LLVMValueRef LHS, LLVMValueRef RHS,
                                   const char *Name, LLVMValueRef* overflow);

LLVMValueRef LLVMBuildUAddOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                   LLVMValueRef LHS, LLVMValueRef RHS,
                                   const char *Name, LLVMValueRef* overflow);

LLVMValueRef LLVMBuildMulOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                  LLVMValueRef LHS, LLVMValueRef RHS,
                                  const char *Name, LLVMValueRef* overflow);

LLVMValueRef LLVMBuildClz(LLVMBuilderRef B, LLVMModuleRef m, LLVMValueRef operand, const char *Name);

void* sljit_create_nvptx_backend();

void sljit_free_nvptx_backend(void* nvptx_backend);

char* generate_ptx(void* nvptx_backend, const char* nvvm_ir);

void free_ptx(char* ptx);

#ifdef __cplusplus
}
#endif /* !defined(__cplusplus) */

#endif /* _LLVM_CPP_WRAPPERS_H_ */
