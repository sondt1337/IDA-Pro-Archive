/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2022 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Handle PC Rust specific data and constructions
 */
#include <map>
#include <ida.hpp>
#include <idp.hpp>
#include "../../module/arm/arm.hpp"
#undef PROCMOD_NODE_NAME
#include "rust.hpp"

// Rust ABI need to be investigated,
// assume callregs:
static const int rv_arm[] = { X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, -1 };

struct arm_rust_t : public proc_rust_t
{
  void init() override
  {
    proc_rust_t::init();
    look_forward = 8;
    if ( is64 )
      regs.set(ARGREGS_GP_ONLY, rv_arm, nullptr);
  }

  uint16 insn_get_rptr(const insn_t &insn) override
  {
    if ( is64 )
    {
      // ADRL X1, aSel
      // ADRP X9, #unk_34C56@PAGE
      return (insn.itype == ARM_adrl || insn.itype == ARM_adrp)
          && insn.Op1.type == o_reg
           ? insn.Op1.reg
           : -1;
    }
    else
    {
      // LDR R0, =(unk_28E30 - 0x32D0)
      return insn.itype == ARM_ldr
          && insn.Op1.type == o_reg
           ? insn.Op1.reg
           : -1;
    }
  }

  uint64 insn_check_for_rlen(const insn_t &insn, uint16 rlen) override
  {
    // MOV W2, #0x20
    // MOVS R1, #0xC
    return insn.itype == ARM_mov
        && insn.Op1.is_reg(rlen)
        && insn.Op2.type == o_imm
         ? insn.Op2.value
         : -1;
  }
};
std::unique_ptr<proc_rust_t> get_arm_rust_handler() { return std::unique_ptr<arm_rust_t>(new arm_rust_t); }  // std::make_unique<arm_rust_t>()
