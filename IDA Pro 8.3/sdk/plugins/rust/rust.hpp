/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2022 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Handle Rust specific data and constructions
 */
#pragma once
#include <memory>
#include <idp.hpp>
#include <typeinf.hpp>

//-------------------------------------------------------------------------
// database
#define PROCMOD_NODE_NAME "$ rust"
// altval(-1) - uint32 rust_ctx_t::flags

//-------------------------------------------------------------------------
// processor module specific Rust handler
struct proc_rust_t
{
  callregs_t regs;
  int look_forward = 5;
  int look_backward = 5;
  bool is64 = true;

  /// to init configuration
  virtual void init()
  {
    is64 = inf_get_app_bitness() == 64;
    regs.reset();
    regs.init_regs(CM_CC_FASTCALL);
  }

  /// check the neighbor instructions of INSN_EA to find the strlit length
  /// \param insn_ea    insn EA which loads of strlit address
  /// \param strlit_ea  strlit EA with dr_O to INSN_EA
  /// \return -1 if not successful
  ///
  /// The default implementation uses the commont patterns for register-based ABI:
  /// 1: load _str.ptr to RPTR register      <- INSN_EA
  ///    - may be several alien insns
  ///    load _str.length to RLEN register
  /// 2: load _str.length to RLEN register
  ///    - may be several alien insns
  ///    load _str.ptr to RPTR register      <- INSN_EA
  virtual uint64 get_strlen(ea_t insn_ea, ea_t /*strlit_ea*/)
  {
    insn_t insn;
    if ( decode_insn(&insn, insn_ea) == 0 )
      return -1;

    uint16 rptr = insn_get_rptr(insn);
    if ( rptr == uint16(-1) )
      return -1;
    uint16 rlen = get_rlen_by_rptr(rptr);
    if ( rlen != uint16(-1) )
    {
      // pattern 1:
      ea_t ea = insn.ea + insn.size;
      for ( int i=0; i < look_forward; ++i )   // number of insn to look forward depends on PROC module
      {
        if ( break_scan(ea) )
          break;
        if ( decode_insn(&insn, ea) == 0 )
          break;
        uint64 strlen = insn_check_for_rlen(insn, rlen);
        if ( strlen != -1 )
          return strlen;
        ea += insn.size;
      }
      // pattern 2:
      ea = insn_ea;
      for ( int i=0; i < look_backward; ++i )   // number of insn to look backward depends on PROC module
      {
        if ( decode_prev_insn(&insn, ea) != BADADDR )
        {
          uint64 strlen = insn_check_for_rlen(insn, rlen);
          if ( strlen != -1 )
            return strlen;
        }
        ea = insn.ea;
        if ( break_scan(ea) )
          break;
      }
    }
    return -1;
  }

  /// callbacks for default get_strlen implementation
  virtual uint16 insn_get_rptr(const insn_t &) { return -1; }
  virtual uint64 insn_check_for_rlen(const insn_t &, uint16 /*rlen*/) { return -1; }

  virtual ~proc_rust_t() {}

protected:
  // helpers

  // _str { data_ptr; length } is placed to two sequential callregs
  // \return register for _str.length or -1
  uint16 get_rlen_by_rptr(uint16 rptr) const
  {
    uint16 rlen = -1;
    int rptr_ind = callregs_t::findreg(regs.gpregs, rptr);
    if ( rptr_ind != -1 && (rptr_ind+1) != regs.gpregs.size() )
      rlen = regs.gpregs[rptr_ind+1];
    return rlen;
  }

  // break insns scan
  bool break_scan(ea_t ea) const
  {
    if ( get_first_fcref_from(ea) != BADADDR )
      return true;

    insn_t insn;
    return decode_insn(&insn, ea) > 0
        && processor_t::is_ret_insn(insn, false) == 1;
  }
};

// module handlers
std::unique_ptr<proc_rust_t> get_pc_rust_handler();
std::unique_ptr<proc_rust_t> get_riscv_rust_handler();
std::unique_ptr<proc_rust_t> get_arm_rust_handler();

//-------------------------------------------------------------------------
struct rust_ctx_t;
DECLARE_LISTENER(idb_listener_t, rust_ctx_t, ctx);
DECLARE_LISTENER(idp_listener_t, rust_ctx_t, ctx);

//-------------------------------------------------------------------------
struct rust_ctx_t : public plugmod_t
{
  idb_listener_t idb_listener = idb_listener_t(*this);
  idp_listener_t idp_listener = idp_listener_t(*this);

  std::unique_ptr<proc_rust_t> mod;
                                ///< module specific Rust handler
  uint32 flags = 0;             ///< plugin flags
#define FLAGS_STRLITS_DONE 0x01 ///< have strlits been analyzed?
  uint32 tuning = 0;            ///< setting to control analisys
#define RTUNE_UNREF_DESC 0x01   ///< allow unreferenced Rust _str literal descriptor
  uint bitness = 64;            ///< application bitness
  bool config_loaded = false;   ///< rust.cfg (-Orust: option) is loaded
  char enabled = -1;            ///< is plugin active? (-1 means not initialized yet)

  rust_ctx_t();
  ~rust_ctx_t();

  bool idaapi run(size_t) override { return true; }

  bool tune_unref_desc() const { return (tuning & RTUNE_UNREF_DESC) != 0; }

private:
  friend idb_listener_t;
  friend idp_listener_t;

  bool strlits_done() const { return (flags & FLAGS_STRLITS_DONE) != 0; }

  // at the beginning, or after undo, initialize the plugin
  void reinit()
  {
    flags = netnode(PROCMOD_NODE_NAME).altval(-1);
  }

  void load_plugin_config();
  void perform_final_strlit_analysis();

  // \return false if cancelled by user
  bool process_strlit_range(const range_t &r);
  asize_t check_for_strlit(ea_t ea, asize_t len);

  void init_mod()
  {
    processor_t &ph = PH;
    switch ( ph.id )
    {
      case PLFM_386:
        mod = get_pc_rust_handler();
        break;
      case PLFM_RISCV:
        mod = get_riscv_rust_handler();
        break;
      case PLFM_ARM:
        mod = get_arm_rust_handler();
        break;
      default:
        mod.release();
        break;
    }
    if ( mod != nullptr )
      mod->init();
  }

  inline uint64 get_strlen(ea_t ea) const;
  uint64 get_mod_strlen(ea_t insn_ea, ea_t strlit_ea)
  {
    return mod != nullptr ? mod->get_strlen(insn_ea, strlit_ea) : -1;
  }

  inline bool make_str(ea_t ea_ptr) const;
};

//-------------------------------------------------------------------------
extern int data_id;
