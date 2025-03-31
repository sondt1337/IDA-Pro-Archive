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
#include <allins.hpp>
#undef PROCMOD_NODE_NAME
#include "rust.hpp"


enum riscv_registers
{
  rX0,  rX1,   rX2,  rX3,   rX4,  rX5,  rX6,  rX7,
  rX8,  rX9,   rX10, rX11,  rX12, rX13, rX14, rX15,
  rX16, rX17,  rX18, rX19,  rX20, rX21, rX22, rX23,
  rX24, rX25,  rX26, rX27,  rX28, rX29, rX30, rX31,
  rF0,  rF1,   rF2,  rF3,   rF4,  rF5,  rF6,  rF7,
  rF8,  rF9,   rF10, rF11,  rF12, rF13, rF14, rF15,
  rF16, rF17,  rF18, rF19,  rF20, rF21, rF22, rF23,
  rF24, rF25,  rF26, rF27,  rF28, rF29, rF30, rF31,
  rV0,  rV1,   rV2,  rV3,   rV4,  rV5,  rV6,  rV7,
  rV8,  rV9,   rV10, rV11,  rV12, rV13, rV14, rV15,
  rV16, rV17,  rV18, rV19,  rV20, rV21, rV22, rV23,
  rV24, rV25,  rV26, rV27,  rV28, rV29, rV30, rV31,
  rPC,  rFCRS, rVcs, rVds,  srGP,
};

// The RISC-V calling convention passes arguments in registers when possible. Up to eight integer
// registers, a0-a7, and up to eight floating-point registers, fa0-fa7, are used for this purpose
//                                a0    a1    a2    a3    a4    a5    a6    a7
static const int rv_riscv[]   = { rX10, rX11, rX12, rX13, rX14, rX15, rX16, rX17, -1 };

struct riscv_rust_t : public proc_rust_t
{
  void init() override
  {
    proc_rust_t::init();
    look_forward = 5;
    // hope to someone will implement ev_get_cc_regs
    regs.set(ARGREGS_GP_ONLY, rv_riscv, nullptr);
  }

  uint16 insn_get_rptr(const insn_t &insn) override
  { // la a0, unk_2672B
    return insn.itype == RISCV_la
        && insn.Op1.type == o_reg
         ? insn.Op1.reg
         : -1;
  }

  uint64 insn_check_for_rlen(const insn_t &insn, uint16 rlen) override
  { // li a1, 21h
    return insn.itype == RISCV_li
        && insn.Op1.is_reg(rlen)
        && insn.Op2.type == o_imm
         ? insn.Op2.value
         : -1;
  }
};
std::unique_ptr<proc_rust_t> get_riscv_rust_handler() { return std::unique_ptr<riscv_rust_t>(new riscv_rust_t); }  // std::make_unique<riscv_rust_t>()
