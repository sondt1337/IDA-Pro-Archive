#if defined(__EA64__) && defined(USE_LIBUNWIND) && !defined(__ANDROID__)
//lint -e750 local macro '' not referenced
  #define HAVE_UPDATE_CALL_STACK
//lint +e750
  #define SET_DBG_OPTIONS set_linux_options
  #define LINUX_NODE "$ local linux options"
#endif

static const char wanted_name[] = "Local Linux debugger";
#define DEBUGGER_NAME  "linux"
#define PROCESSOR_NAME "metapc"
#define TARGET_PROCESSOR PLFM_386
#define DEBUGGER_ID    DEBUGGER_ID_X86_IA32_LINUX_USER
#define DEBUGGER_FLAGS (DBG_FLAG_LOWCNDS  \
                      | DBG_FLAG_DEBTHREAD)
#define DEBUGGER_RESMOD (DBG_RESMOD_STEP_INTO)
#define HAVE_APPCALL
#define S_FILETYPE     f_ELF

#include <fpro.h>
#include <idd.hpp>
#include <ua.hpp>
#include <range.hpp>
#include <loader.hpp>
#include "linux_debmod.h"

linux_debmod_t g_dbgmod;
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "linux_local_impl.cpp"
#include "common_local_impl.cpp"
