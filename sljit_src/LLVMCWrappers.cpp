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

#include "LLVMCWrappers.h"

#if !(defined SLJIT_NO_DEFAULT_CONFIG && SLJIT_NO_DEFAULT_CONFIG)
#include "sljitConfig.h"
#endif

#include "sljitConfigInternal.h"

#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>

#include <algorithm>
#include <vector>

LLVMValueRef LLVMBuildIntrinsicOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                        const llvm::Intrinsic::ID intrinsic_id,
                                        LLVMValueRef LHS, LLVMValueRef RHS,
                                        const char *Name, LLVMValueRef* overflow) {
  auto ir_builder = llvm::unwrap(B);
  auto arg_ty = llvm::unwrap(LLVMTypeOf(LHS));
  auto intrinsic = llvm::Intrinsic::getDeclaration(
    llvm::unwrap(m),
    intrinsic_id,
    std::vector<llvm::Type*> { arg_ty });
  SLJIT_ASSERT(intrinsic);
  auto val_and_flag = ir_builder->CreateCall2(
    intrinsic,
    llvm::unwrap(LHS),
    llvm::unwrap(RHS),
    Name);
  auto val = ir_builder->CreateExtractValue(val_and_flag, { 0 });
  auto flag = ir_builder->CreateExtractValue(val_and_flag, { 1 });
  *overflow = llvm::wrap(flag);
  return llvm::wrap(val);
}

extern "C" {

LLVMValueRef LLVMBuildAddOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                  LLVMValueRef LHS, LLVMValueRef RHS,
                                  const char *Name, LLVMValueRef* overflow) {
  return LLVMBuildIntrinsicOverflow(B, m, llvm::Intrinsic::sadd_with_overflow, LHS, RHS, Name, overflow);
}

LLVMValueRef LLVMBuildSubOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                  LLVMValueRef LHS, LLVMValueRef RHS,
                                  const char *Name, LLVMValueRef* overflow) {
  return LLVMBuildIntrinsicOverflow(B, m, llvm::Intrinsic::ssub_with_overflow, LHS, RHS, Name, overflow);
}

LLVMValueRef LLVMBuildUSubOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                   LLVMValueRef LHS, LLVMValueRef RHS,
                                   const char *Name, LLVMValueRef* overflow) {
  return LLVMBuildIntrinsicOverflow(B, m, llvm::Intrinsic::usub_with_overflow, LHS, RHS, Name, overflow);
}

LLVMValueRef LLVMBuildUAddOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                   LLVMValueRef LHS, LLVMValueRef RHS,
                                   const char *Name, LLVMValueRef* overflow) {
  return LLVMBuildIntrinsicOverflow(B, m, llvm::Intrinsic::uadd_with_overflow, LHS, RHS, Name, overflow);
}

LLVMValueRef LLVMBuildMulOverflow(LLVMBuilderRef B, LLVMModuleRef m,
                                  LLVMValueRef LHS, LLVMValueRef RHS,
                                  const char *Name, LLVMValueRef* overflow) {
  return LLVMBuildIntrinsicOverflow(B, m, llvm::Intrinsic::smul_with_overflow, LHS, RHS, Name, overflow);
}

LLVMValueRef LLVMBuildClz(LLVMBuilderRef B, LLVMModuleRef m, LLVMValueRef operand, const char *Name) {
  auto ir_builder = llvm::unwrap(B);
  auto operand_ty = llvm::unwrap(LLVMTypeOf(operand));
  auto mod = llvm::unwrap(m);
  auto intrinsic = llvm::Intrinsic::getDeclaration(
    llvm::unwrap(m),
    llvm::Intrinsic::ctlz,
    std::vector<llvm::Type*> { operand_ty });
  SLJIT_ASSERT(intrinsic);
  auto bool_type = llvm::IntegerType::get(mod->getContext(), 1);
  auto bool_false = llvm::ConstantInt::get(bool_type, 0);
  return llvm::wrap(ir_builder->CreateCall2(intrinsic, llvm::unwrap(operand), bool_false, Name));
}

}
