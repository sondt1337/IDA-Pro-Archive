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
#include <intel.hpp>
#undef PROCMOD_NODE_NAME
#include "rust.hpp"

struct pc_rust_t : public proc_rust_t
{
  /// check the neighbor instructions of INSN_EA to find the strlit length
  /// \return -1 if not successful
  uint64 get_strlen(ea_t insn_ea, ea_t strlit_ea) override;

  uint16 insn_get_rptr(const insn_t &insn) override
  { // lea rax, aImagine
    return insn.itype == NN_lea
        && insn.Op1.type == o_reg
         ? insn.Op1.reg
         : -1;
  }

  uint64 insn_check_for_rlen(const insn_t &insn, uint16 rlen) override
  { // mov esi, 1Ch         ; .len (_str.length)
    return insn.itype == NN_mov
        && insn.Op1.is_reg(rlen)
        && insn.Op2.type == o_imm
         ? insn.Op2.value
         : -1;
  }

private:
  bool is_rlen_stk_insn(const insn_t &insn, uval_t stkoff) const
  { // mov [rsp+238h+var_60.length], 7
    return insn.itype == NN_mov
        && insn.Op1.type == o_displ
        && insn.Op1.reg == R_sp
        && insn.Op1.addr == stkoff + sizeof(ea_t)
        && insn.Op2.type == o_imm;
  }

protected:
};

//-------------------------------------------------------------------------
std::unique_ptr<proc_rust_t> get_pc_rust_handler() { return std::unique_ptr<pc_rust_t>(new pc_rust_t); }  // std::make_unique<pc_rust_t>()

//-------------------------------------------------------------------------
uint64 pc_rust_t::get_strlen(ea_t insn_ea, ea_t strlit_ea)
{
  uint64 strlen = proc_rust_t::get_strlen(insn_ea, strlit_ea);
  if ( strlen != -1 )
    return strlen;

  if ( is64 )
  {
    insn_t insn;
    if ( decode_insn(&insn, insn_ea) == 0 )
      return -1;
    uint16 rptr = insn_get_rptr(insn);
    if ( rptr != uint16(-1) )
    {
      ea_t next_ea = insn.ea + insn.size;
      if ( decode_insn(&insn, next_ea) == 0 )
        return -1;
      // lea rax, aImagine
      // mov [rsp+238h+var_60.data_ptr], rax
      // mov [rsp+238h+var_60.length], 7
      if ( insn.itype == NN_mov
        && insn.Op1.type == o_displ
        && insn.Op1.reg == R_sp
        && insn.Op2.is_reg(rptr) )
      {
        uval_t stkoff = insn.Op1.addr;
        if ( decode_insn(&insn, next_ea+insn.size) > 0
          && is_rlen_stk_insn(insn, stkoff) )
        {
          return insn.Op2.value;
        }
      }
    }

    // .text:000000014009E009                 lea     rdx, unk_1401D0BF5
    // .text:000000014009E010                 jmp     loc_14009E199
    // .text:000000014009E015 ; ---------------------------------------------------------------------------
    // .text:000000014009E015 loc_14009E015:
    // .text:000000014009E015                 mov     rcx, [rsi+20h]  ; jumptable 000000014009DEBA case 14
    // .text:000000014009E019                 mov     rax, [rsi+28h]
    // .text:000000014009E01D                 mov     rax, [rax+18h]
    // .text:000000014009E021                 lea     rdx, unk_1401D0BEC
    // .text:000000014009E028                 mov     r8d, 9
    // .text:000000014009E02E                 jmp     loc_14009E229

    // .text:000000000001DF0E                 lea     rax, unk_40AE0  ; jumptable 000000000001DCEB case 33
    // .text:000000000001DF15                 mov     ecx, 10h
    // .text:000000000001DF1A                 jmp     short loc_1DF7C
    //
  }
  return -1;
}
