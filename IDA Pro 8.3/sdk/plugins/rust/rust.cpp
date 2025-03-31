/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2022 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 *      Handle Rust specific data and constructions
 */

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <loader.hpp>
#include <diskio.hpp>


#include "rust.hpp"

//-------------------------------------------------------------------------
int data_id;

// .rodata segment names
static const char *const rust_strlit_names[] =
{
  "__const",
  ".rodata",
  ".rdata",
};

//-------------------------------------------------------------------------
// #define PDEB    // uncomment for debugging
#ifndef TESTABLE_BUILD
#undef PDEB
#endif
#ifdef PDEB
AS_PRINTF(1, 2) inline int pdeb(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int nbytes = vmsg(format, va);
  va_end(va);
  return nbytes;
}
#else
AS_PRINTF(1, 2) inline int pdeb(const char *, ...) { return 0; }
#endif

//-------------------------------------------------------------------------
// dd str_ptr
// dd str_len
// or
// dq str_ptr
// dq str_len
inline uint64 rust_ctx_t::get_strlen(ea_t ea_ptr) const
{
  return bitness == 32 ? get_dword(ea_ptr + 4) : get_qword(ea_ptr + 8);
}

inline bool rust_ctx_t::make_str(ea_t ea_ptr) const
{
  // TODO apply type
  uint bytes = bitness/8;
  ea_t ea_len = ea_ptr + bytes;
  asize_t sz_len = bytes;
  return is_head(get_flags(ea_len))
      && get_item_size(ea_len) != sz_len
      && (bitness == 32
        ? create_dword(ea_len, sz_len, true)
        : create_qword(ea_len, sz_len, true));

}

//-------------------------------------------------------------------------
rust_ctx_t::rust_ctx_t()
{
  load_plugin_config();
  hook_event_listener(HT_IDB, &idb_listener);
  hook_event_listener(HT_IDP, &idp_listener);
  tuning = RTUNE_UNREF_DESC;
  if ( enabled )
    reinit();
}

rust_ctx_t::~rust_ctx_t()
{
  clr_module_data(data_id);
}

//-------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list va)
{
  qnotused(va);
  if ( !ctx.enabled )
    return 0;
  switch ( code )
  {
    case idb_event::compiler_changed:
      break;

    case idb_event::auto_empty:
      ctx.bitness = inf_get_app_bitness();
      ctx.init_mod();
      show_wait_box("Creating Rust-specific string literals");
      ctx.perform_final_strlit_analysis();
      hide_wait_box();
      break;

    case idb_event::closebase:
      break;
  }
  return 0;
}

//---------------------------------------------------------------------------
ssize_t idaapi idp_listener_t::on_event(ssize_t code, va_list va)
{
  qnotused(va);
  // in any case plugin must handle MERGE or CVT64 actions
  switch ( code )
  {
#ifdef ENABLE_MERGE
#endif

#ifdef CVT64
    case processor_t::ev_cvt64_supval:
      {
        netnode helper = netnode(PROCMOD_NODE_NAME);
        static const cvt64_node_tag_t node_info[] =
        {
          { CVT64_NODE_IDP_FLAGS },
        };
        return cvt64_node_supval_for_event(va, node_info, qnumber(node_info));
      }
      break;
#endif
  }

  // for the next actions plugin must be active
  if ( !ctx.enabled )
    return 0;
  switch ( code )
  {
    case processor_t::ev_ending_undo:
      ctx.reinit();
      break;

    case processor_t::ev_newfile:
      ctx.bitness = inf_get_app_bitness();
      ctx.init_mod();
      break;

    case processor_t::ev_oldfile:
    case processor_t::ev_newprc:
      ctx.bitness = inf_get_app_bitness();
      ctx.init_mod();
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
// We have done AU_TYPE for the entire program.
// Try to find the strlits and create the missed strings.
// RUST does not use string pool,
// string literal is an ordinary constant and
// can be alternated with the other constants
void rust_ctx_t::perform_final_strlit_analysis()
{
  if ( strlits_done() )
    return; // done this once, it is enough
  // remember that we analyzed strlits
  flags |= FLAGS_STRLITS_DONE;
  netnode(PROCMOD_NODE_NAME, 0, true).altset(-1, flags);

  // f_MACHO may have several segs named "__const"
  int qty = get_segm_qty();
  for ( int i=0; i < qty; ++i )
  {
    segment_t *s = getnseg(i);
    qstring sname;
    if ( get_segm_name(&sname, s) > 0 )
    {
      for ( const auto pn : rust_strlit_names )
      {
        if ( sname.ends_with(pn) )
          if ( !process_strlit_range(*s) )
            break;
      }
    }
  }
}

//-------------------------------------------------------------------------
// create strlits in range identified by xref:
// * get EA with xref
// * check for strlit
// * adjust length using next xref
// * create strlit
bool rust_ctx_t::process_strlit_range(const range_t &r)
{
  pdeb("RUST: process_strlit_range %a..%a\n", r.start_ea, r.end_ea);
  constexpr int alopts = ALOPT_IGNHEADS | ALOPT_IGNPRINT | ALOPT_IGNCLT;

  uint minbytes = bitness/8;
  ea_t ea = r.start_ea;
  while ( ea < r.end_ea )
  {
    if ( user_cancelled() )
      return false;
    asize_t len = get_max_strlit_length(ea, STRTYPE_C, alopts);
    if ( len <= minbytes )   // FIXME
    { // let skip small strlit
      ea = next_that(ea, r.end_ea, f_has_xref);
      continue;
    }
    ea_t end = next_that(ea, ea + len, f_has_xref);
    if ( end != BADADDR )
      len = end - ea;
    len = check_for_strlit(ea, len);
    ea = ea + len;
  }
  return true;
}

//--------------------------------------------------------------------------
// Create strlit if it has meaning.
// We should be completely sure to create a strlit
// otherwise we produce a mess:
// * try to check the xref'ed places
//   and may be to adjust the length
// * do not forget about the classic C-like 0-terminated strings
asize_t rust_ctx_t::check_for_strlit(ea_t ea, asize_t len)
{
  // assert: len != 0
  pdeb("RUST: check_for_strlit %a..%a\n", ea, ea+len);

  // Usually the difference between adjusted length and
  // input length should less then 3.
  // Turned out that find the false descriptor for C-like string is easy.
  constexpr int max_len_delta = 3;

  asize_t adjlen = 0; // adjusted length
  int trust_counter = 0;

  // at first check drefs as the more reliable way
  eavec_t drefs;
  xrefblk_t xb;
  for ( bool ok=xb.first_to(ea, XREF_DATA); ok; ok=xb.next_to() )
  {
    if ( xb.type != dr_O )
      continue;
    ea_t from = xb.from;
    flags64_t F = get_flags(from);
    if ( is_data(F) && (tune_unref_desc() || has_xref(F)) )
    {
      uint64 detected_len = get_strlen(from);
      if ( detected_len > len )
        continue;   // false alarm, must be string length at least
      if ( adjlen == 0 )
        adjlen = detected_len;
      else if ( adjlen != detected_len )
        goto RET;   // every ref must describe the same strlit
      trust_counter++;
      drefs.push_back(from);
    }
  }

  if ( adjlen == 0 )
  { // finally check crefs
    for ( bool ok=xb.first_to(ea, XREF_DATA); ok; ok=xb.next_to() )
    {
      if ( xb.type != dr_O )
        continue;
      ea_t from = xb.from;
      flags64_t F = get_flags(from);
      if ( is_code(F) )
      {
        uint64 detected_len = get_mod_strlen(from, ea);
        if ( detected_len != -1 )
        {
          if ( adjlen == 0 )
            adjlen = detected_len;
          else if ( adjlen != detected_len )
            goto RET;   // every ref must describe the same strlit
          trust_counter++;
        }
      }
    }
  }

  if ( adjlen != 0
    && adjlen <= len
    && (trust_counter > 1 || (len - adjlen) < max_len_delta) )
  {
    pdeb("RUST: strlit %a..%a\n", ea, ea+adjlen);
    len = adjlen;
    flags64_t F = get_flags(ea);
    if ( is_tail(F) )
    { // preserve the strlit item head to decrease the mess
      ea_t head = get_item_head(ea);
      if ( is_strlit(get_flags(head)) )
      {
        del_items(head, DELIT_SIMPLE, ea-head);
        create_strlit(head, ea-head, STRTYPE_C);
      }
    }
    asize_t itemsz = get_item_size(ea);
    del_items(ea, DELIT_SIMPLE, len);
    create_strlit(ea, len, STRTYPE_C);
    if ( is_strlit(F) )
    { // preserve the strlit item tail to decrease the mess
      if ( len < (itemsz-1) ) // do not touch the last byte
        create_strlit(ea+len, itemsz-len, STRTYPE_C);
      else if ( len == itemsz-1 ) // the last byte
        create_byte(ea+len, 1, true);
    }
    for ( auto dea : drefs )
      make_str(dea);
  }
RET:
  return len;
}

//--------------------------------------------------------------------------
bool detect_rust_binary()
{
  ea_t ea = get_name_ea(BADADDR, "rust_begin_unwind");
  if ( ea != BADADDR )
    return true;

  // search only in .rodata if it exists
  ea_t ea1 = 0;
  ea_t ea2 = BADADDR;
  segment_t *s = get_segm_by_name(".rodata");
  if ( s != nullptr )
  {
    ea1 = s->start_ea;
    ea2 = s->end_ea;
  }

  static const uchar ptn[] = "rustc-";
  int flags = BIN_SEARCH_CASE | BIN_SEARCH_NOBREAK | BIN_SEARCH_FORWARD;
  ea = bin_search2(ea1, ea2, ptn, nullptr, sizeof(ptn)-1, flags);
  return ea != BADADDR;
}

//--------------------------------------------------------------------------
static const cfgopt_t cfg_options[] =
{
  CFGOPT_N("ENABLE_RUST", rust_ctx_t, enabled),
  CFGOPT_N("ANALYSIS_OPTIONS", rust_ctx_t, tuning),
};

//-------------------------------------------------------------------------
static void take_note_about_rust_file()
{
#ifdef TESTABLE_BUILD
  qstring path;
  qgetenv("HOME", &path);
  path.append("/rust.log");
  FILE *fp = fopenA(path.c_str());
  if ( fp != nullptr )
  {
    char buf[QMAXPATH];
    get_input_file_path(buf, sizeof(buf));
    qstrncat(buf, "\n", sizeof(buf));
    qfputs(buf, fp);
    qfclose(fp);
  }
#endif
}

//-------------------------------------------------------------------------
void rust_ctx_t::load_plugin_config()
{
  if ( config_loaded )
    return;

  // rust.cfg config file
  read_config_file2("rust",
                    cfg_options, qnumber(cfg_options),
                    nullptr,                    // defhdlr
                    nullptr,                    // defines
                    0,                          // ndefines
                    this);                      // obj

  bool note_rust_files = false;
  qstring options = get_plugin_options("rust");
  qvector<qstring> tokens;
  options.split(&tokens, ":");
  for ( const qstring &tok: tokens )
  {
    if ( tok == "on" )
      enabled = true;
    else if ( tok == "off" )
      enabled = false;
#ifdef TESTABLE_BUILD
    else if ( tok.starts_with("tune=") )
    {
      tuning = atoi(tok.begin() + 5);
    }
    else if ( tok.starts_with("note") )
    {
      note_rust_files = true;
    }
#endif
    else
      error("rust: invalid command line option \"%s\"", tok.c_str());
  }
  config_loaded = true;

  if ( enabled == -1 )
  {
    enabled = detect_rust_binary();
    if ( enabled )
    {
      msg("RUST: the input file probably contains Rust code\n");
      if ( note_rust_files )
        take_note_about_rust_file();
    }
  }

  if ( enabled )
  {
    msg("RUST: plugin has been enabled\n");
  }
}

//-------------------------------------------------------------------------
// Create a plugin context and return it to the kernel.
static plugmod_t *idaapi init()
{
  return new rust_ctx_t;
}

//-------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI|PLUGIN_MOD,
  init,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  "Rust language helper",
  nullptr,
};
