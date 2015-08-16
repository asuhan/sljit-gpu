/*
 *    Stack-less Just-In-Time compiler
 *
 *    Copyright 2009-2012 Zoltan Herczeg (hzmester@freemail.hu). All rights reserved.
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

#include "sljitLir.h"
#include "LLVMCWrappers.h"

SLJIT_API_FUNC_ATTRIBUTE SLJIT_CONST char* sljit_get_platform_name(void)
{
	return "LLVM" SLJIT_CPUINFO;
}

SLJIT_API_FUNC_ATTRIBUTE void* sljit_generate_code(struct sljit_compiler *compiler)
{
	SLJIT_ASSERT(0);
}

static LLVMValueRef llvm_flag_e(const struct sljit_compiler* compiler) {
	LLVMValueRef flag_idx_lv = LLVMConstInt(LLVMInt32Type(), 0, 0);
	return LLVMBuildGEP(
		compiler->llvm_builder,
		compiler->llvm_flags,
		&flag_idx_lv,
		1,
		"flag_e_access");
}

static LLVMValueRef llvm_flag_c(const struct sljit_compiler* compiler) {
	LLVMValueRef flag_idx_lv = LLVMConstInt(LLVMInt32Type(), 1, 0);
	return LLVMBuildGEP(
		compiler->llvm_builder,
		compiler->llvm_flags,
		&flag_idx_lv,
		1,
		"flag_u_access");
}

static LLVMValueRef llvm_flag_s(const struct sljit_compiler* compiler) {
	LLVMValueRef flag_idx_lv = LLVMConstInt(LLVMInt32Type(), 2, 0);
	return LLVMBuildGEP(
		compiler->llvm_builder,
		compiler->llvm_flags,
		&flag_idx_lv,
		1,
		"flag_s_access");
}

static LLVMValueRef llvm_flag_o(const struct sljit_compiler* compiler) {
	LLVMValueRef flag_idx_lv = LLVMConstInt(LLVMInt32Type(), 3, 0);
	return LLVMBuildGEP(
		compiler->llvm_builder,
		compiler->llvm_flags,
		&flag_idx_lv,
		1,
		"flag_o_access");
}

static void reset_flags(const struct sljit_compiler* compiler) {
	const unsigned long long flag_count = 4;
	unsigned long long flag_idx;
	for (flag_idx = 0; flag_idx < flag_count; ++flag_idx) {
		LLVMValueRef flag_idx_lv = LLVMConstInt(LLVMInt32Type(), flag_idx, 0);
		LLVMBuildStore(compiler->llvm_builder, LLVMConstInt(LLVMInt1Type(), 0, 0),
			LLVMBuildGEP(
				compiler->llvm_builder,
				compiler->llvm_flags,
				&flag_idx_lv,
				1,
				"flag_access"));
	}
}

void sljit_free_llvm_compiler_impl(struct sljit_compiler *compiler) {
	LLVMDisposeBuilder(compiler->llvm_builder);
}

void sljit_llvm_free_code_impl(struct sljit_compiler *compiler) {
	// TODO(alex)
	// LLVMDisposeExecutionEngine(compiler->llvm_engine);
}

static LLVMValueRef ll_int(const sljit_sw val, unsigned num_bits) {
	return LLVMConstInt(LLVMIntType(num_bits), val, 0);
}

static LLVMValueRef ll_i64(const sljit_sw val)
{
	return ll_int(val, 64);
}

SLJIT_API_FUNC_ATTRIBUTE void* sljit_llvm_generate_code(struct sljit_compiler *compiler)
{
	char *error = NULL;
	LLVMValueRef func = LLVMGetFirstFunction(compiler->llvm_module);

	while (func) {
		unsigned bb_count = LLVMCountBasicBlocks(func);
		LLVMBasicBlockRef bb_list[bb_count];
		unsigned i;

		LLVMGetBasicBlocks(func, bb_list);
		for (i = 0; i < bb_count; ++i) {
			if (!LLVMGetBasicBlockTerminator(bb_list[i])) {
				LLVMPositionBuilderAtEnd(compiler->llvm_builder, bb_list[i]);
				LLVMBuildRet(compiler->llvm_builder, ll_i64(-666));
			}
		}
		func = LLVMGetNextFunction(func);
	}

	LLVMVerifyModule(compiler->llvm_module, LLVMAbortProcessAction, &error);
	LLVMDisposeMessage(error);

	LLVMExecutionEngineRef engine;
	error = NULL;

	LLVMInitializeNativeTarget();
	LLVMInitializeAllTargetMCs();
	LLVMInitializeAllAsmPrinters();
	LLVMLinkInMCJIT();

	if (LLVMCreateExecutionEngineForModule(&engine, compiler->llvm_module, &error) != 0) {
		fprintf(stderr, "failed to create execution engine\n");
		puts(error);
		abort();
	}
	if (error) {
		fprintf(stderr, "error: %s\n", error);
		LLVMDisposeMessage(error);
		exit(EXIT_FAILURE);
	}

	compiler->error = SLJIT_ERR_COMPILED;
	compiler->llvm_native_code = (void*) LLVMGetFunctionAddress(engine, "anon_func");
	compiler->executable_size = 1;

	return compiler->llvm_native_code;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_set_context(struct sljit_compiler *compiler,
	sljit_si options, sljit_si args, sljit_si scratches, sljit_si saveds,
	sljit_si fscratches, sljit_si fsaveds, sljit_si local_size)
{
	// TODO(alex)
	return SLJIT_SUCCESS;
}

/* --------------------------------------------------------------------- */
/*  Operators                                                            */
/* --------------------------------------------------------------------- */

static LLVMValueRef reg_access(sljit_si reg, struct sljit_compiler *compiler)
{
	SLJIT_ASSERT(reg >= 1 && reg <= SLJIT_NUMBER_OF_REGISTERS + 4);
	LLVMValueRef reg_idx_lv = LLVMConstInt(LLVMInt32Type(), reg - 1, 0);
	return LLVMBuildGEP(
		compiler->llvm_builder,
		compiler->llvm_regs,
		&reg_idx_lv,
		1,
		"reg_access");
}

static LLVMValueRef reg_load(sljit_si reg, struct sljit_compiler *compiler)
{
	return LLVMBuildLoad(compiler->llvm_builder, reg_access(reg, compiler), "reg_load");
}

static void reg_write(LLVMValueRef reg, LLVMValueRef val, struct sljit_compiler *compiler, const sljit_si int_op)
{
	SLJIT_ASSERT(reg);
	SLJIT_ASSERT(LLVMGetTypeKind(LLVMTypeOf(reg)) == LLVMPointerTypeKind);
	if (int_op) {
		LLVMTypeRef reg_val_ty = LLVMGetElementType(LLVMTypeOf(reg));
		SLJIT_ASSERT(LLVMGetTypeKind(reg_val_ty) == LLVMIntegerTypeKind &&
			(LLVMGetIntTypeWidth(reg_val_ty) == 32 ||
			LLVMGetIntTypeWidth(reg_val_ty) == 64)
		);
		SLJIT_ASSERT(
			LLVMGetTypeKind(LLVMTypeOf(val)) == LLVMIntegerTypeKind &&
			LLVMGetIntTypeWidth(LLVMTypeOf(val)) == 32);
		if (reg_val_ty != LLVMTypeOf(val)) {
			LLVMValueRef dest_val = LLVMBuildLoad(compiler->llvm_builder, reg,
				"dest_int_op_64");
			LLVMValueRef dest_val_h = LLVMBuildAnd(compiler->llvm_builder, dest_val, ll_i64(~((1L << 32) - 1)),
				"dest_int_op_masked");
			LLVMValueRef src_val = LLVMBuildZExt(compiler->llvm_builder, val, reg_val_ty,
				"src_int_op_masked");
			val = LLVMBuildOr(compiler->llvm_builder, dest_val_h, src_val,
				"dest_and_src");
		}
	}
	LLVMBuildStore(compiler->llvm_builder, val, reg);
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_enter(struct sljit_compiler *compiler,
	sljit_si options, sljit_si args, sljit_si scratches, sljit_si saveds,
	sljit_si fscratches, sljit_si fsaveds, sljit_si local_size)
{
	LLVMTypeRef param_types[args];
	sljit_si i;

	for (i = 0; i < args; ++i) {
		param_types[i] = LLVMInt64Type();
	}
	LLVMTypeRef fn_type = LLVMFunctionType(LLVMInt64Type(), param_types, args, 0);
	compiler->llvm_func = LLVMAddFunction(compiler->llvm_module, "anon_func", fn_type);
	compiler->llvm_builder = LLVMCreateBuilder();

	LLVMBasicBlockRef entry = LLVMAppendBasicBlock(compiler->llvm_func, "entry");
	LLVMPositionBuilderAtEnd(compiler->llvm_builder, entry);
	compiler->llvm_regs = LLVMBuildArrayAlloca(
		compiler->llvm_builder,
		LLVMInt64Type(),
		LLVMConstInt(LLVMInt8Type(), SLJIT_NUMBER_OF_REGISTERS + 4, 0),
		"registers");
	const unsigned long long flag_count = 4;
	compiler->llvm_flags = LLVMBuildArrayAlloca(
		compiler->llvm_builder,
		LLVMInt1Type(),
		LLVMConstInt(LLVMInt8Type(), flag_count, 0),
		"flags");
	reset_flags(compiler);
	if (local_size) {
		SLJIT_ASSERT(local_size % 8 == 0);
		LLVMValueRef locals = LLVMBuildArrayAlloca(
			compiler->llvm_builder,
			LLVMInt64Type(),
			LLVMConstInt(LLVMInt8Type(), local_size >> 3, 0),
			"locals");
		LLVMValueRef locals_i64 = LLVMBuildPtrToInt(
			compiler->llvm_builder, locals, LLVMInt64Type(), "locals_i64");
		reg_write(reg_access(SLJIT_SP, compiler), locals_i64, compiler, 0);
	}

	for (i = 0; i < args; ++i) {
		reg_write(
			reg_access(SLJIT_S(i), compiler),
			LLVMGetParam(compiler->llvm_func, i),
			compiler,
			0);
	}

	return SLJIT_SUCCESS;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_return(struct sljit_compiler *compiler, sljit_si op, sljit_si src, sljit_sw srcw)
{
	switch (op) {
	case SLJIT_MOV:
	case SLJIT_MOV_SB: {
		sljit_emit_op1(compiler, op, SLJIT_RETURN_REG, 0, src, srcw);
		LLVMBuildRet(compiler->llvm_builder, reg_load(SLJIT_RETURN_REG, compiler));
		break;
	}
	case SLJIT_UNUSED: {
		LLVMBuildRet(compiler->llvm_builder, reg_load(SLJIT_RETURN_REG, compiler));
		break;
	}
	default:
		SLJIT_ASSERT(0);
	}

	return SLJIT_SUCCESS;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_fast_enter(struct sljit_compiler *compiler, sljit_si dst, sljit_sw dstw)
{
	SLJIT_ASSERT(0);
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_fast_return(struct sljit_compiler *compiler, sljit_si src, sljit_sw srcw)
{
	SLJIT_ASSERT(0);
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_op0(struct sljit_compiler *compiler, sljit_si op)
{
	unsigned num_bits = (op & SLJIT_INT_OP) ? 32 : 64;
	switch (GET_OPCODE(op)) {
	case SLJIT_LUMUL:
	case SLJIT_LSMUL: {
		SLJIT_ASSERT(num_bits == 64);
		LLVMValueRef lhs_lv = reg_load(SLJIT_R(0), compiler);
		LLVMValueRef rhs_lv = reg_load(SLJIT_R(1), compiler);
		if (GET_OPCODE(op) == SLJIT_LUMUL) {
			lhs_lv = LLVMBuildZExt(compiler->llvm_builder, lhs_lv, LLVMIntType(128), "zext_lumul");
			rhs_lv = LLVMBuildZExt(compiler->llvm_builder, rhs_lv, LLVMIntType(128), "zext_lumul");
		} else {
			lhs_lv = LLVMBuildSExt(compiler->llvm_builder, lhs_lv, LLVMIntType(128), "zext_lumul");
			rhs_lv = LLVMBuildSExt(compiler->llvm_builder, rhs_lv, LLVMIntType(128), "zext_lumul");
		}
		LLVMValueRef result = LLVMBuildMul(compiler->llvm_builder, lhs_lv, rhs_lv, "lmul");
		LLVMValueRef low = LLVMBuildTrunc(compiler->llvm_builder, result, LLVMInt64Type(), "lmul_low");
		reg_write(reg_access(SLJIT_R(0), compiler), low, compiler, 0);
		LLVMValueRef high = LLVMBuildLShr(compiler->llvm_builder, result, ll_int(64, 128), "lmul_high");
		high = LLVMBuildTrunc(compiler->llvm_builder, high, LLVMInt64Type(), "lmul_high");
		reg_write(reg_access(SLJIT_R(1), compiler), high, compiler, 0);
		break;
	}
	case SLJIT_LUDIV:
	case SLJIT_LSDIV: {
		LLVMValueRef lhs_lv = reg_load(SLJIT_R(0), compiler);
		LLVMValueRef rhs_lv = reg_load(SLJIT_R(1), compiler);
		if (num_bits == 32) {
			lhs_lv = LLVMBuildTrunc(compiler->llvm_builder, lhs_lv, LLVMInt32Type(), "ldiv_lhs");
			rhs_lv = LLVMBuildTrunc(compiler->llvm_builder, rhs_lv, LLVMInt32Type(), "ldiv_rhs");
		}
		LLVMValueRef res = (GET_OPCODE(op) == SLJIT_LUDIV)
			? LLVMBuildUDiv(compiler->llvm_builder, lhs_lv, rhs_lv, "ldiv_res")
			: LLVMBuildSDiv(compiler->llvm_builder, lhs_lv, rhs_lv, "ldiv_res");
		LLVMValueRef rem = (GET_OPCODE(op) == SLJIT_LUDIV)
			? LLVMBuildURem(compiler->llvm_builder, lhs_lv, rhs_lv, "ldiv_rem")
			: LLVMBuildSRem(compiler->llvm_builder, lhs_lv, rhs_lv, "ldiv_rem");
		reg_write(reg_access(SLJIT_R(0), compiler), res, compiler, num_bits == 32);
		reg_write(reg_access(SLJIT_R(1), compiler), rem, compiler, num_bits == 32);
		break;
	}
	case SLJIT_NOP:
		return SLJIT_SUCCESS;
	default:
		SLJIT_ASSERT(0);
	}

	return SLJIT_SUCCESS;
}

static LLVMValueRef mem_access_1(sljit_si reg, sljit_sw regw, struct sljit_compiler *compiler, unsigned num_bits, sljit_si update)
{
	sljit_si addr_reg = reg & REG_MASK;
	LLVMValueRef reg_or_zero = addr_reg > 0 ? reg_load(addr_reg, compiler) : ll_i64(0);
	LLVMValueRef addr_i64 = LLVMBuildAdd(
		compiler->llvm_builder,
		reg_or_zero,
		ll_i64(regw),
		"reg_imm_addr");
	if (update && addr_reg > 0) {
		reg_write(reg_access(addr_reg, compiler), addr_i64, compiler, 0);
	}
	return LLVMBuildIntToPtr(
		compiler->llvm_builder,
		addr_i64,
		LLVMPointerType(LLVMIntType(num_bits), 0),
		"bitcast_addr_idx");
}

static LLVMValueRef mem_access_2(sljit_si regs, sljit_sw shiftw, struct sljit_compiler *compiler, unsigned num_bits, sljit_si update)
{
	sljit_si idx_reg = (regs & REG_MASK);
	sljit_si off_reg = (regs & OFFS_REG_MASK) >> 8;
	LLVMValueRef idx_lv = reg_load(idx_reg, compiler);
	LLVMValueRef off_lv = reg_load(off_reg, compiler);
	off_lv = LLVMBuildShl(
		compiler->llvm_builder,
		off_lv,
		ll_i64(shiftw),
		"offset_shift");
	off_lv = LLVMBuildAdd(
		compiler->llvm_builder,
		idx_lv,
		off_lv,
		"offset_add");
	if (update) {
		reg_write(reg_access(idx_reg, compiler), off_lv, compiler, 0);
	}
	return LLVMBuildIntToPtr(
		compiler->llvm_builder,
		off_lv,
		LLVMPointerType(LLVMIntType(num_bits), 0),
		"bitcast_addr");
}

static LLVMValueRef emit_dst(
	struct sljit_compiler *compiler,
	sljit_si dst,
	sljit_sw dstw,
	unsigned num_bits,
	sljit_si update)
{
	LLVMValueRef dest_lv = NULL;
	if (FAST_IS_REG(dst)) {
		dest_lv = reg_access(dst, compiler);
	}
	else if (dst & SLJIT_MEM)
	{
		if ((dst & OFFS_REG_MASK) == 0) {
			dest_lv = mem_access_1(dst, dstw, compiler, num_bits, update);
		}
		else {
			dest_lv = mem_access_2(dst, dstw, compiler, num_bits, update);
		}
	}
	else {
		SLJIT_ASSERT(0);
	}
	return dest_lv;
}

static LLVMValueRef emit_src(
	struct sljit_compiler *compiler,
	sljit_si src,
	sljit_sw srcw,
	unsigned num_bits,
	sljit_si update)
{
	LLVMValueRef src_lv = NULL;
	if (src & SLJIT_IMM) {
		src_lv = ll_int(srcw, num_bits);
	}
	else if (FAST_IS_REG(src)) {
		src_lv = reg_load(src, compiler);
	}
	else if (src & SLJIT_MEM) {
		if ((src & OFFS_REG_MASK) == 0) {
			src_lv = LLVMBuildLoad(
				compiler->llvm_builder,
				mem_access_1(src, srcw, compiler, num_bits, update),
				"mem_load_1");
		}
		else {
			src_lv = LLVMBuildLoad(
				compiler->llvm_builder,
				mem_access_2(src, srcw, compiler, num_bits, update),
				"mem_load_2");
		}
	}
	else {
		SLJIT_ASSERT(0);
	}
	LLVMTypeRef src_ty = LLVMTypeOf(src_lv);
	SLJIT_ASSERT(LLVMGetTypeKind(src_ty) == LLVMIntegerTypeKind);
	if (LLVMGetIntTypeWidth(src_ty) < num_bits) {
		src_lv = LLVMBuildSExt(
			compiler->llvm_builder,
			src_lv,
			LLVMIntType(num_bits),
			"src_sext");
	} else if (LLVMGetIntTypeWidth(src_ty) > num_bits) {
		src_lv = LLVMBuildTrunc(
			compiler->llvm_builder,
			src_lv,
			LLVMIntType(num_bits),
			"src_trunc");
	}
	return src_lv;
}

static unsigned mov_num_bits(sljit_si op) {
	sljit_si op_flags = GET_ALL_FLAGS(op);
	op = GET_OPCODE(op);

	switch (op) {
	case SLJIT_MOV_SB:
	case SLJIT_MOV_UB:
	case SLJIT_MOVU_SB:
	case SLJIT_MOVU_UB:
		SLJIT_ASSERT(!op_flags);
		return 8;
	case SLJIT_MOV_SH:
	case SLJIT_MOV_UH:
	case SLJIT_MOVU_SH:
	case SLJIT_MOVU_UH:
		SLJIT_ASSERT(!op_flags);
		return 16;
		break;
	case SLJIT_MOV_SI:
	case SLJIT_MOV_UI:
	case SLJIT_MOVU_SI:
	case SLJIT_MOVU_UI:
		return 32;
		break;
	case SLJIT_MOV:
	case SLJIT_MOV_P:
	case SLJIT_MOVU_P:
	case SLJIT_MOVU:
	case SLJIT_NOT:
	case SLJIT_NEG:
	case SLJIT_CLZ:
		return (op_flags & SLJIT_INT_OP) ? 32 : 64;
		break;
	default:
		SLJIT_ASSERT(0);
		break;
	}
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_op1(struct sljit_compiler *compiler, sljit_si op,
	sljit_si dst, sljit_sw dstw,
	sljit_si src, sljit_sw srcw)
{
	sljit_si update = 0;
	sljit_si op_flags = GET_ALL_FLAGS(op);
	unsigned num_bits = 0;

	CHECK_ERROR();

	op = GET_OPCODE(op);

	if (op != SLJIT_NEG && op != SLJIT_NOT && dst == SLJIT_UNUSED) {
		return SLJIT_SUCCESS;
	}

	if (op >= SLJIT_MOV && op <= SLJIT_MOVU_P) {
		if (op >= SLJIT_MOVU) {
			update = 1;
		}
	}

	switch (op) {
	case SLJIT_MOV_SB:
	case SLJIT_MOV_UB:
	case SLJIT_MOVU_SB:
	case SLJIT_MOVU_UB:
		SLJIT_ASSERT(!op_flags);
		num_bits = 8;
		break;
	case SLJIT_MOV_SH:
	case SLJIT_MOV_UH:
	case SLJIT_MOVU_SH:
	case SLJIT_MOVU_UH:
		SLJIT_ASSERT(!op_flags);
		num_bits = 16;
		break;
	case SLJIT_MOV_SI:
	case SLJIT_MOV_UI:
	case SLJIT_MOVU_SI:
	case SLJIT_MOVU_UI:
		num_bits = 32;
		break;
	case SLJIT_MOV:
	case SLJIT_MOV_P:
	case SLJIT_MOVU_P:
	case SLJIT_MOVU:
	case SLJIT_NOT:
	case SLJIT_NEG:
	case SLJIT_CLZ:
		num_bits = (op_flags & SLJIT_INT_OP) ? 32 : 64;
		break;
	default:
		SLJIT_ASSERT(0);
		break;
	}

	LLVMValueRef dest_lv = NULL;

	LLVMValueRef src_lv = emit_src(compiler, src, srcw, num_bits, update);
	LLVMTypeRef src_ty = LLVMTypeOf(src_lv);
	SLJIT_ASSERT(LLVMGetTypeKind(src_ty) == LLVMIntegerTypeKind);

	if (dst != SLJIT_UNUSED) {
		dest_lv = emit_dst(compiler, dst, dstw, num_bits, update);
		SLJIT_ASSERT(LLVMGetTypeKind(LLVMTypeOf(dest_lv)) == LLVMPointerTypeKind);
		LLVMTypeRef dest_ty = LLVMGetElementType(LLVMTypeOf(dest_lv));
		SLJIT_ASSERT(LLVMGetTypeKind(dest_ty) == LLVMIntegerTypeKind);
	}

	LLVMValueRef result = NULL;
	LLVMValueRef overflow_flag = NULL;

	switch (op) {
	case SLJIT_MOV:
	case SLJIT_MOV_P:
	case SLJIT_MOVU_P:
	case SLJIT_MOVU:
	case SLJIT_MOV_SI:
	case SLJIT_MOV_UI:
	case SLJIT_MOVU_SI:
	case SLJIT_MOVU_UI:
	case SLJIT_MOV_SH:
	case SLJIT_MOV_UH:
	case SLJIT_MOVU_SH:
	case SLJIT_MOVU_UH:
	case SLJIT_MOV_SB:
	case SLJIT_MOV_UB:
	case SLJIT_MOVU_SB:
	case SLJIT_MOVU_UB:
		result = src_lv;
		break;
	case SLJIT_NOT: {
		result = LLVMBuildNot(compiler->llvm_builder, src_lv, "not");
		break;
	}
	case SLJIT_NEG: {
		if (op_flags & SLJIT_SET_O) {
			result = LLVMBuildSubOverflow(compiler->llvm_builder, compiler->llvm_module,
				ll_int(0, LLVMGetIntTypeWidth(src_ty)), src_lv, "neg_of", &overflow_flag);
		} else {
			result = LLVMBuildNeg(compiler->llvm_builder, src_lv, "neg");
		}
		break;
	}
	case SLJIT_CLZ: {
		result = LLVMBuildClz(compiler->llvm_builder, compiler->llvm_module, src_lv, "clz");
		break;
	}
	default:
		SLJIT_ASSERT(0);
		break;
	}

	if (dst != SLJIT_UNUSED) {
		SLJIT_ASSERT(dest_lv);
		LLVMTypeRef result_ty = LLVMTypeOf(result);
		LLVMTypeRef dest_ty = LLVMGetElementType(LLVMTypeOf(dest_lv));
		if (LLVMGetIntTypeWidth(result_ty) < LLVMGetIntTypeWidth(dest_ty)) {
			result = (op & 1)
				? LLVMBuildZExt(compiler->llvm_builder, result, dest_ty, "src_zext")
				: LLVMBuildSExt(compiler->llvm_builder, result, dest_ty, "src_sext");
		} else if (LLVMGetIntTypeWidth(result_ty) > LLVMGetIntTypeWidth(dest_ty)) {
			result = LLVMBuildTrunc(compiler->llvm_builder, result, dest_ty, "src_trunc");
		}
		reg_write(dest_lv, result, compiler, 0);
	}

	if (op_flags & SLJIT_SET_E) {
		LLVMValueRef e_lv = LLVMBuildICmp(
			compiler->llvm_builder,
			LLVMIntEQ,
			result,
			ll_int(0, op == SLJIT_CLZ ? 64 : num_bits),
			"set_e");
		LLVMBuildStore(compiler->llvm_builder, e_lv, llvm_flag_e(compiler));
	}
	if (op_flags & SLJIT_SET_O) {
		SLJIT_ASSERT(overflow_flag);
		LLVMBuildStore(compiler->llvm_builder, overflow_flag, llvm_flag_o(compiler));
	}
	if (op_flags & SLJIT_SET_C) {
		// TODO
	}
	if (op_flags & SLJIT_SET_S) {
		// TODO
	}
	if (op_flags & SLJIT_SET_U) {
		// TODO
	}
	return SLJIT_SUCCESS;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_op2(struct sljit_compiler *compiler, sljit_si op,
	sljit_si dst, sljit_sw dstw,
	sljit_si src1, sljit_sw src1w,
	sljit_si src2, sljit_sw src2w)
{
	sljit_si flags = GET_ALL_FLAGS(op);
	unsigned num_bits = (flags & SLJIT_INT_OP) ? 32 : 64;
	LLVMValueRef dest_lv = dst == SLJIT_UNUSED ? NULL : emit_dst(compiler, dst, dstw, num_bits, 0);
	LLVMValueRef lhs = emit_src(compiler, src1, src1w, num_bits, 0);
	LLVMValueRef rhs = emit_src(compiler, src2, src2w, num_bits, 0);
	LLVMValueRef result = NULL;
	LLVMValueRef overflow_flag = NULL;

	LLVMValueRef flag_c_ptr = llvm_flag_c(compiler);
        LLVMValueRef flag_c = LLVMBuildLoad(compiler->llvm_builder, flag_c_ptr, "flag_c");
	sljit_si with_overflow = flags && !(flags & SLJIT_KEEP_FLAGS);

	switch (GET_OPCODE(op)) {
	case SLJIT_ADD:
	case SLJIT_ADDC: {
		if (with_overflow) {
			result = LLVMBuildAddOverflow(
				compiler->llvm_builder,
				compiler->llvm_module,
				lhs,
				rhs,
				GET_OPCODE(op) == SLJIT_ADD ? "op_add" : "op_addc",
				&overflow_flag);
		} else {
			result = LLVMBuildAdd(
				compiler->llvm_builder,
				lhs,
				rhs,
				GET_OPCODE(op) == SLJIT_ADD ? "op_add" : "op_addc");
		}
		if (GET_OPCODE(op) == SLJIT_ADDC) {
			result = LLVMBuildAdd(
				compiler->llvm_builder,
				result,
				LLVMBuildZExt(
					compiler->llvm_builder,
					flag_c,
					LLVMIntType(num_bits),
					"op_addc"),
				"op_addc");
		}
		break;
	}
	case SLJIT_AND:
		result = LLVMBuildAnd(compiler->llvm_builder, lhs, rhs, "op_and");
		break;
	case SLJIT_OR:
		result = LLVMBuildOr(compiler->llvm_builder, lhs, rhs, "op_or");
		break;
	case SLJIT_XOR:
		result = LLVMBuildXor(compiler->llvm_builder, lhs, rhs, "op_xor");
		break;
	case SLJIT_MUL:
		if (with_overflow) {
			result = LLVMBuildMulOverflow(
				compiler->llvm_builder,
				compiler->llvm_module,
				lhs,
				rhs,
				"op_mul",
				&overflow_flag);
		} else {
			result = LLVMBuildMul(
				compiler->llvm_builder,
				lhs,
				rhs,
				"op_mul");
		}
		break;
	case SLJIT_SUB:
	case SLJIT_SUBC: {
		if (GET_OPCODE(op) == SLJIT_SUBC) {
			if (with_overflow) {
				rhs = LLVMBuildAddOverflow(
					compiler->llvm_builder,
					compiler->llvm_module,
					lhs,
					LLVMBuildZExt(
						compiler->llvm_builder,
						flag_c, LLVMIntType(num_bits),
						"op_subc"),
					"op_subc",
					&overflow_flag);
			} else {
				rhs = LLVMBuildAdd(
					compiler->llvm_builder,
					rhs,
					LLVMBuildZExt(
						compiler->llvm_builder,
						flag_c, LLVMIntType(num_bits),
						"op_subc"),
					"op_subc");
			}
		}
		if (with_overflow) {
			result = LLVMBuildSubOverflow(compiler->llvm_builder, compiler->llvm_module,
				lhs, rhs, GET_OPCODE(op) == SLJIT_SUB ? "op_sub" : "op_subc", &overflow_flag);
		} else {
			result = LLVMBuildSub(compiler->llvm_builder, lhs, rhs,
				GET_OPCODE(op) == SLJIT_SUB ? "op_sub" : "op_subc");
		}
		break;
	}
	case SLJIT_LSHR: {
		rhs = LLVMBuildAnd(compiler->llvm_builder, rhs, ll_int(num_bits == 32 ? 31 : 63, num_bits), "mask_shift_count");
		result = LLVMBuildLShr(compiler->llvm_builder, lhs, rhs, "op_lshr");
		break;
	}
	case SLJIT_ASHR: {
		rhs = LLVMBuildAnd(compiler->llvm_builder, rhs, ll_int(num_bits == 32 ? 31 : 63, num_bits), "mask_shift_count");
		result = LLVMBuildAShr(compiler->llvm_builder, lhs, rhs, "op_ashr");
		break;
	}
	case SLJIT_SHL: {
		rhs = LLVMBuildAnd(compiler->llvm_builder, rhs, ll_int(num_bits == 32 ? 31 : 63, num_bits), "mask_shift_count");
		result = LLVMBuildShl(compiler->llvm_builder, lhs, rhs, "op_shl");
		break;
	}
	default:
		SLJIT_ASSERT(0);
		break;
	}

	if (dst != SLJIT_UNUSED) {
		SLJIT_ASSERT(dest_lv);
		reg_write(dest_lv, result, compiler, flags & SLJIT_INT_OP);
	}
	if (with_overflow) {
		LLVMValueRef e_lv = LLVMBuildICmp(
			compiler->llvm_builder,
			LLVMIntEQ,
			result,
			ll_int(0, num_bits),
			"set_e");
		LLVMBuildStore(compiler->llvm_builder, e_lv, llvm_flag_e(compiler));
		if ((flags & SLJIT_SET_U) || (flags & SLJIT_SET_C) || (flags & SLJIT_SET_S)) {
			LLVMValueRef c_lv = NULL;
			if (GET_OPCODE(op) == SLJIT_SUB || GET_OPCODE(op) == SLJIT_SUBC) {
				if (GET_OPCODE(op) == SLJIT_SUB) {
					LLVMBuildUSubOverflow(
						compiler->llvm_builder,
						compiler->llvm_module,
						lhs, rhs, "set_c", &c_lv);
				} else {
					// TODO(alex): fix
					c_lv = LLVMConstInt(LLVMInt1Type(), 1, 0);
				}
			} else {
				SLJIT_ASSERT(GET_OPCODE(op) == SLJIT_ADD || GET_OPCODE(op) == SLJIT_ADDC);
				LLVMBuildUAddOverflow(
					compiler->llvm_builder,
					compiler->llvm_module,
					lhs, rhs, "set_c", &c_lv);
			}
			LLVMBuildStore(compiler->llvm_builder, c_lv, llvm_flag_c(compiler));
			LLVMValueRef s_lv = LLVMBuildICmp(
				compiler->llvm_builder,
				LLVMIntSLT,
				lhs,
				rhs,
				"set_s");
			LLVMBuildStore(compiler->llvm_builder, s_lv, llvm_flag_s(compiler));
		}
		else if (flags & SLJIT_SET_O) {
			LLVMBuildStore(compiler->llvm_builder, overflow_flag, llvm_flag_o(compiler));
		}
		else if (flags & SLJIT_SET_E) {
		}
		else if (flags & SLJIT_INT_OP) {
		}
		else if (flags & SLJIT_KEEP_FLAGS) {
		}
		else {
			SLJIT_ASSERT(0);
		}
	}

	return SLJIT_SUCCESS;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_get_register_index(sljit_si reg)
{
	SLJIT_ASSERT(0);
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_get_float_register_index(sljit_si reg)
{
	SLJIT_ASSERT(0);
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_op_custom(struct sljit_compiler *compiler,
	void *instruction, sljit_si size)
{
	SLJIT_ASSERT(0);
}

/* --------------------------------------------------------------------- */
/*  Floating point operators                                             */
/* --------------------------------------------------------------------- */

static void init_compiler(void)
{
	// TODO(alex)
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_is_fpu_available(void)
{
	// TODO(alex)
	return 0;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_fop1(struct sljit_compiler *compiler, sljit_si op,
	sljit_si dst, sljit_sw dstw,
	sljit_si src, sljit_sw srcw)
{
	SLJIT_ASSERT(0);
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_fop2(struct sljit_compiler *compiler, sljit_si op,
	sljit_si dst, sljit_sw dstw,
	sljit_si src1, sljit_sw src1w,
	sljit_si src2, sljit_sw src2w)
{
	SLJIT_ASSERT(0);
}

/* --------------------------------------------------------------------- */
/*  Conditional instructions                                             */
/* --------------------------------------------------------------------- */

LLVMValueRef create_cont_function(LLVMModuleRef module, const char is_jump) {
	LLVMTypeRef param_types[2];
	param_types[0] = LLVMPointerType(LLVMInt64Type(), 0);
	param_types[1] = LLVMPointerType(LLVMInt1Type(), 0);
	LLVMTypeRef cont_type = LLVMFunctionType(LLVMInt64Type(), param_types, 2, 0);
	LLVMValueRef cont_func = LLVMAddFunction(module, is_jump ? (is_jump > 1 ? "stub_cont" : "jump_cont") : "label_cont", cont_type);
	LLVMAppendBasicBlock(cont_func, "entry");
	return cont_func;
}

SLJIT_API_FUNC_ATTRIBUTE struct sljit_label* sljit_emit_label(struct sljit_compiler *compiler)
{
	struct sljit_label *label = NULL;
	LLVMValueRef cont_func = create_cont_function(compiler->llvm_module, 0);
	LLVMValueRef cont_args[2];

	cont_args[0] = compiler->llvm_regs;
	cont_args[1] = compiler->llvm_flags;

	label = malloc(sizeof(struct sljit_label));
	PTR_FAIL_IF(!label);

	LLVMBasicBlockRef current_bb = LLVMGetInsertBlock(compiler->llvm_builder);
	if (!LLVMGetBasicBlockTerminator(current_bb)) {
	  LLVMBuildRet(
		  compiler->llvm_builder,
		  LLVMBuildCall(
			compiler->llvm_builder,
			cont_func,
			cont_args,
			2,
			"call_label_cont"));
	}
	LLVMPositionBuilderAtEnd(compiler->llvm_builder, LLVMGetEntryBasicBlock(cont_func));
	label->addr = cont_func;

	compiler->llvm_regs = LLVMGetParam(cont_func, 0);
	compiler->llvm_flags = LLVMGetParam(cont_func, 1);
	compiler->llvm_func = cont_func;

	return label;
}

static LLVMValueRef load_flag(struct sljit_compiler *compiler, sljit_si type) {
	LLVMValueRef flag;
	type &= 0xff;
	switch (type) {
	case SLJIT_LESS:
	case SLJIT_LESS_EQUAL:
	case SLJIT_GREATER:
	case SLJIT_GREATER_EQUAL: {
		LLVMValueRef flag_c_ptr = llvm_flag_c(compiler);
		flag = LLVMBuildLoad(compiler->llvm_builder, flag_c_ptr, "flag_c");
		if (type == SLJIT_GREATER || type == SLJIT_GREATER_EQUAL) {
			flag = LLVMBuildNot(compiler->llvm_builder, flag, "flag_nc");
		}
		break;
	}
	case SLJIT_SIG_LESS:
	case SLJIT_SIG_LESS_EQUAL:
	case SLJIT_SIG_GREATER:
	case SLJIT_SIG_GREATER_EQUAL: {
		LLVMValueRef flag_s_ptr = llvm_flag_s(compiler);
		flag = LLVMBuildLoad(compiler->llvm_builder, flag_s_ptr, "flag_s");
		if (type == SLJIT_SIG_GREATER || type == SLJIT_SIG_GREATER_EQUAL) {
			flag = LLVMBuildNot(compiler->llvm_builder, flag, "flag_ns");
		}
		break;
	}
	case SLJIT_EQUAL:
	case SLJIT_NOT_EQUAL: {
		LLVMValueRef flag_e_ptr = llvm_flag_e(compiler);
		flag = LLVMBuildLoad(compiler->llvm_builder, flag_e_ptr, "flag_e");
		if (type == SLJIT_NOT_EQUAL) {
			flag = LLVMBuildNot(compiler->llvm_builder, flag, "flag_ne");
		}
		break;
	}
	case SLJIT_OVERFLOW:
	case SLJIT_NOT_OVERFLOW:
	case SLJIT_MUL_OVERFLOW:
	case SLJIT_MUL_NOT_OVERFLOW:{
		LLVMValueRef flag_o_ptr = llvm_flag_o(compiler);
		flag = LLVMBuildLoad(compiler->llvm_builder, flag_o_ptr, "flag_o");
		if (type == SLJIT_NOT_OVERFLOW || type == SLJIT_MUL_NOT_OVERFLOW) {
			flag = LLVMBuildNot(compiler->llvm_builder, flag, "flag_no");
		}
		break;
	}
	case SLJIT_JUMP: {
		flag = LLVMConstInt(LLVMInt1Type(), 0, 0);
		break;
	}
	default: {
		SLJIT_ASSERT(0);
		break;
	}
	}
	switch (type) {
	case SLJIT_LESS_EQUAL:
	case SLJIT_GREATER:
	case SLJIT_SIG_LESS_EQUAL:
	case SLJIT_SIG_GREATER: {
		LLVMValueRef flag_e_ptr = llvm_flag_e(compiler);
		LLVMValueRef flag_e = LLVMBuildLoad(compiler->llvm_builder, flag_e_ptr, "flag_e");
		if (type == SLJIT_GREATER || type == SLJIT_SIG_GREATER) {
			LLVMValueRef flag_ne = LLVMBuildNot(compiler->llvm_builder, flag_e, "flag_ne");
			flag = LLVMBuildAnd(compiler->llvm_builder, flag, flag_ne, "flag_and_ne");
		} else {
			flag = LLVMBuildOr(compiler->llvm_builder, flag, flag_e, "flag_or_e");
		}
	}
	default:
		break;
	}
	return flag;
}

SLJIT_API_FUNC_ATTRIBUTE struct sljit_jump* sljit_emit_jump(struct sljit_compiler *compiler, sljit_si type)
{
	struct sljit_jump *jump = NULL;
	LLVMValueRef flag = NULL;
	LLVMValueRef stub_func = NULL;
	LLVMValueRef cont_args[2];

	cont_args[0] = compiler->llvm_regs;
	cont_args[1] = compiler->llvm_flags;

	// TODO(alex)
	// SLJIT_ASSERT(!(type & SLJIT_REWRITABLE_JUMP));

	type &= 0xff;
	switch (type) {
	case SLJIT_SIG_LESS:
	case SLJIT_LESS:
	case SLJIT_LESS_EQUAL:
	case SLJIT_SIG_LESS_EQUAL:
	case SLJIT_GREATER:
	case SLJIT_SIG_GREATER:
	case SLJIT_GREATER_EQUAL:
	case SLJIT_SIG_GREATER_EQUAL:
	case SLJIT_EQUAL:
	case SLJIT_JUMP:
	case SLJIT_NOT_EQUAL:
	case SLJIT_MUL_NOT_OVERFLOW:
	case SLJIT_MUL_OVERFLOW:
	case SLJIT_OVERFLOW:
	case SLJIT_NOT_OVERFLOW:
		flag = load_flag(compiler, type);
		flag = LLVMBuildNot(compiler->llvm_builder, flag, "not_flag");
		break;
	case SLJIT_CALL0:
	case SLJIT_CALL1:
	case SLJIT_CALL2:
	case SLJIT_CALL3: {
		stub_func = create_cont_function(compiler->llvm_module, 2);
		break;
	}
	default:
		SLJIT_ASSERT(0);
		break;
	}
	LLVMValueRef cont_func = NULL;
	if (!stub_func) {
		LLVMBasicBlockRef flag_false = LLVMAppendBasicBlock(compiler->llvm_func, "flag_false");
		LLVMBasicBlockRef flag_true = LLVMAppendBasicBlock(compiler->llvm_func, "flag_true");
		LLVMBuildCondBr(compiler->llvm_builder, flag, flag_false, flag_true);
		LLVMPositionBuilderAtEnd(compiler->llvm_builder, flag_true);
		cont_func = create_cont_function(compiler->llvm_module, 1);
		LLVMBuildRet(
			compiler->llvm_builder,
			LLVMBuildCall(compiler->llvm_builder,
			cont_func,
			cont_args,
			2,
			"call_jump_cont"));
		LLVMPositionBuilderAtEnd(compiler->llvm_builder, flag_false);
	} else {
		SLJIT_ASSERT(SLJIT_CALL0 <= type && type <= SLJIT_CALL3);
		size_t arity = type - SLJIT_CALL0;
		LLVMValueRef copied_regs = LLVMBuildArrayAlloca(
			compiler->llvm_builder,
			LLVMInt64Type(),
			LLVMConstInt(LLVMInt8Type(), SLJIT_NUMBER_OF_REGISTERS + 4, 0),
			"saved_registers");
		LLVMValueRef copied_flags = LLVMBuildArrayAlloca(
			compiler->llvm_builder,
			LLVMInt1Type(),
			LLVMConstInt(LLVMInt8Type(), 5, 0),
			"saved_flags");
		size_t idx = 0;
		for (idx = 0; idx < SLJIT_NUMBER_OF_REGISTERS + 4; ++idx) {
			LLVMValueRef idx_lv = LLVMConstInt(LLVMInt32Type(), idx, 0);
			LLVMValueRef orig_reg_ptr = LLVMBuildGEP(
				compiler->llvm_builder,
				cont_args[0],
				&idx_lv,
				1,
				"orig_reg_ptr");
			LLVMValueRef orig_reg = LLVMBuildLoad(compiler->llvm_builder, orig_reg_ptr, "orig_reg");
			LLVMValueRef copied_reg_ptr = LLVMBuildGEP(
				compiler->llvm_builder,
				copied_regs,
				&idx_lv,
				1,
				"copied_reg_ptr");
			LLVMBuildStore(compiler->llvm_builder, orig_reg, copied_reg_ptr);
		}
		for (idx = 0; idx < arity; ++idx) {
			LLVMValueRef idx_lv = LLVMConstInt(LLVMInt32Type(), SLJIT_S(idx) - 1, 0);
			LLVMValueRef saved_reg_ptr = LLVMBuildGEP(
				compiler->llvm_builder,
				copied_regs,
				&idx_lv,
				1,
				"saved_reg_ptr");
			LLVMBuildStore(compiler->llvm_builder, reg_load(SLJIT_R(idx), compiler), saved_reg_ptr);
		}
		for (idx = 0; idx < 5; ++idx) {
			LLVMValueRef idx_lv = LLVMConstInt(LLVMInt32Type(), idx, 0);
			LLVMValueRef orig_flag_ptr = LLVMBuildGEP(
				compiler->llvm_builder,
				cont_args[1],
				&idx_lv,
				1,
				"orig_flag_ptr");
			LLVMValueRef orig_flag = LLVMBuildLoad(compiler->llvm_builder, orig_flag_ptr, "orig_flag");
			LLVMValueRef copied_flag_ptr = LLVMBuildGEP(
				compiler->llvm_builder,
				copied_flags,
				&idx_lv,
				1,
				"copied_flag_ptr");
			LLVMBuildStore(compiler->llvm_builder, orig_flag, copied_flag_ptr);
		}
		cont_args[0] = copied_regs;
		cont_args[1] = copied_flags;
		LLVMValueRef ret = LLVMBuildCall(
			compiler->llvm_builder,
			stub_func,
			cont_args,
			2,
			"stub_call");
		reg_write(reg_access(SLJIT_RETURN_REG, compiler), ret, compiler, 0);
	}
	jump = malloc(sizeof(struct sljit_jump));
	PTR_FAIL_IF_NULL(jump);
	set_jump(jump, compiler, type & SLJIT_REWRITABLE_JUMP);
	jump->addr = (stub_func ? stub_func : cont_func);
	return jump;
}

SLJIT_API_FUNC_ATTRIBUTE void sljit_llvm_set_label(struct sljit_compiler *compiler, struct sljit_jump *jump, struct sljit_label* label) {
	LLVMBasicBlockRef saved = LLVMGetInsertBlock(compiler->llvm_builder);
	LLVMPositionBuilderAtEnd(compiler->llvm_builder, LLVMGetEntryBasicBlock(jump->addr));
	LLVMValueRef cont_args[2];
	cont_args[0] = LLVMGetParam(jump->addr, 0);
	cont_args[1] = LLVMGetParam(jump->addr, 1);
	LLVMBuildRet(compiler->llvm_builder, LLVMBuildCall(compiler->llvm_builder, label->addr, cont_args, 2, "call_cont_label"));
	LLVMPositionBuilderAtEnd(compiler->llvm_builder, saved);
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_ijump(struct sljit_compiler *compiler, sljit_si type, sljit_si src, sljit_sw srcw)
{
	switch (type) {
	case SLJIT_CALL0:
	case SLJIT_CALL1:
	case SLJIT_CALL2:
	case SLJIT_CALL3: {
		const size_t arity = type - SLJIT_CALL0;
		LLVMValueRef args[arity];
		LLVMTypeRef param_types[arity];
		size_t i;
		for (i = 0; i < arity; ++i) {
			args[i] = reg_load(SLJIT_R(i), compiler);
		}
		for (i = 0; i < arity; ++i) {
			param_types[i] = LLVMInt64Type();
		}
		LLVMTypeRef fn_type = LLVMPointerType(LLVMFunctionType(LLVMInt64Type(), param_types, arity, 0), 0);
		LLVMValueRef fn_ptr = emit_src(compiler, src, srcw, 64, 0);
		fn_ptr = LLVMBuildIntToPtr(compiler->llvm_builder, fn_ptr, fn_type, "fn_ptr");
		LLVMValueRef ret = LLVMBuildCall(
			compiler->llvm_builder,
			fn_ptr,
			args,
			arity,
			"ijump_call");
		reg_write(reg_access(SLJIT_RETURN_REG, compiler), ret, compiler, 0);
		break;
	}
	case SLJIT_JUMP: {
		LLVMValueRef cont_args[2];
		cont_args[0] = compiler->llvm_regs;
		cont_args[1] = compiler->llvm_flags;
		LLVMTypeRef param_types[2];
		param_types[0] = LLVMTypeOf(cont_args[0]);
		param_types[1] = LLVMTypeOf(cont_args[1]);
		LLVMTypeRef fn_type = LLVMPointerType(LLVMFunctionType(LLVMInt64Type(), param_types, 2, 0), 0);
		LLVMValueRef fn_ptr = emit_src(compiler, src, srcw, 64, 0);
		fn_ptr = LLVMBuildIntToPtr(compiler->llvm_builder, fn_ptr, fn_type, "fn_ptr");
		LLVMBuildCall(
			compiler->llvm_builder,
			fn_ptr,
			cont_args,
			2,
			"ijump_jump");
		break;
	}
	default:
		SLJIT_ASSERT(0);
	}
	return SLJIT_SUCCESS;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_emit_op_flags(struct sljit_compiler *compiler, sljit_si op,
	sljit_si dst, sljit_sw dstw,
	sljit_si src, sljit_sw srcw,
	sljit_si type)
{
	if (dst == SLJIT_UNUSED) {
		return SLJIT_SUCCESS;
	}
	sljit_si opcode = GET_OPCODE(op);
	SLJIT_ASSERT(opcode == SLJIT_OR || opcode == SLJIT_AND || opcode == SLJIT_XOR ||
		(opcode >= SLJIT_MOV && opcode <= SLJIT_MOVU_P));
	unsigned num_bits = (opcode >= SLJIT_MOV && opcode <= SLJIT_MOVU_P)
		? mov_num_bits(opcode)
		: (op & SLJIT_INT_OP) ? 32 : 64;
	LLVMValueRef src_lv = src == SLJIT_UNUSED ? NULL : emit_src(compiler, src, srcw, num_bits, 0);
	LLVMValueRef dest_lv = emit_dst(compiler, dst, dstw, num_bits, 0);
	LLVMValueRef flag_lv = load_flag(compiler, type);
	LLVMValueRef orig_flag_lv = flag_lv;
	flag_lv = LLVMBuildZExt(compiler->llvm_builder, flag_lv, LLVMIntType(num_bits), "zext_flag");
	if (opcode == SLJIT_OR) {
		if (src == SLJIT_UNUSED) {
			return SLJIT_SUCCESS;
		}
		SLJIT_ASSERT(src_lv);
		flag_lv = LLVMBuildOr(compiler->llvm_builder, src_lv, flag_lv, "flag_or");
	}
	if (opcode == SLJIT_AND) {
		SLJIT_ASSERT(src_lv);
		flag_lv = LLVMBuildAnd(compiler->llvm_builder, src_lv, flag_lv, "flag_and");
	}
	if (opcode == SLJIT_XOR) {
		SLJIT_ASSERT(src_lv);
		flag_lv = LLVMBuildXor(compiler->llvm_builder, src_lv, flag_lv, "flag_xor");
	}
	reg_write(dest_lv, flag_lv, compiler, num_bits == 32);
	sljit_si flags = GET_ALL_FLAGS(op);
	if (flags & SLJIT_SET_U) {
		SLJIT_ASSERT(0);
	}
	if (flags & SLJIT_SET_S) {
		SLJIT_ASSERT(0);
	}
	if (flags & SLJIT_SET_O) {
		SLJIT_ASSERT(0);
	}
	if (flags & SLJIT_SET_C) {
		SLJIT_ASSERT(0);
	}
	// TODO: fix
	if ((flags & SLJIT_SET_E) && (opcode != SLJIT_AND || FAST_IS_REG(dst))) {
		SLJIT_ASSERT(type == SLJIT_EQUAL || type == SLJIT_NOT_EQUAL);
		LLVMBuildStore(
			compiler->llvm_builder,
			LLVMBuildICmp(
				compiler->llvm_builder,
				LLVMIntEQ,
				orig_flag_lv,
				type == SLJIT_EQUAL ? ll_int(0, 1) : ll_int(1, 1),
				"op_flags_set_e"),
			llvm_flag_e(compiler));
	}
	return SLJIT_SUCCESS;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_si sljit_get_local_base(struct sljit_compiler *compiler, sljit_si dst, sljit_sw dstw, sljit_sw offset)
{
	LLVMValueRef dest_lv = emit_dst(compiler, dst, dstw, 64, 0);
	reg_write(dest_lv, LLVMBuildAdd(compiler->llvm_builder,
		reg_load(SLJIT_SP, compiler), ll_i64(offset), "locals_off"), compiler, 0);
	return SLJIT_SUCCESS;
}

SLJIT_API_FUNC_ATTRIBUTE struct sljit_const* sljit_emit_const(struct sljit_compiler *compiler, sljit_si dst, sljit_sw dstw, sljit_sw init_value)
{
	// TODO(alex)
	return NULL;
}

SLJIT_API_FUNC_ATTRIBUTE void sljit_set_jump_addr(sljit_uw addr, sljit_uw new_addr)
{

	SLJIT_ASSERT(0);
}

SLJIT_API_FUNC_ATTRIBUTE void sljit_set_const(sljit_uw addr, sljit_sw new_constant)
{
	SLJIT_ASSERT(0);
}
