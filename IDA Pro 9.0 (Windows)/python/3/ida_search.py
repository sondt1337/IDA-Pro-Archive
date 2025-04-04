r"""
Middle-level search functions.

They all are controlled by Search flags"""

from sys import version_info as _swig_python_version_info
# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_search
else:
    import _ida_search

try:
    import builtins as __builtin__
except ImportError:
    import __builtin__

def _swig_repr(self):
    try:
        strthis = "proxy of " + self.this.__repr__()
    except __builtin__.Exception:
        strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)


def _swig_setattr_nondynamic_instance_variable(set):
    def set_instance_attr(self, name, value):
        if name == "this":
            set(self, name, value)
        elif name == "thisown":
            self.this.own(value)
        elif hasattr(self, name) and isinstance(getattr(type(self), name), property):
            set(self, name, value)
        else:
            raise AttributeError("You cannot add instance attributes to %s" % self)
    return set_instance_attr


def _swig_setattr_nondynamic_class_variable(set):
    def set_class_attr(cls, name, value):
        if hasattr(cls, name) and not isinstance(getattr(cls, name), property):
            set(cls, name, value)
        else:
            raise AttributeError("You cannot add class attributes to %s" % cls)
    return set_class_attr


def _swig_add_metaclass(metaclass):
    """Class decorator for adding a metaclass to a SWIG wrapped class - a slimmed down version of six.add_metaclass"""
    def wrapper(cls):
        return metaclass(cls.__name__, cls.__bases__, cls.__dict__.copy())
    return wrapper


class _SwigNonDynamicMeta(type):
    """Meta class to enforce nondynamic attributes (no new attributes) for a class"""
    __setattr__ = _swig_setattr_nondynamic_class_variable(type.__setattr__)


import weakref

SWIG_PYTHON_LEGACY_BOOL = _ida_search.SWIG_PYTHON_LEGACY_BOOL

import ida_idaapi


#<pycode(py_search)>
#</pycode(py_search)>

SEARCH_UP = _ida_search.SEARCH_UP
r"""
search towards lower addresses
"""

SEARCH_DOWN = _ida_search.SEARCH_DOWN
r"""
search towards higher addresses
"""

SEARCH_NEXT = _ida_search.SEARCH_NEXT
r"""
skip the starting address when searching. this bit is useful only for search(),
bin_search(), find_reg_access(). find_.. functions skip the starting address
automatically.
"""

SEARCH_CASE = _ida_search.SEARCH_CASE
r"""
case-sensitive search (case-insensitive otherwise)
"""

SEARCH_REGEX = _ida_search.SEARCH_REGEX
r"""
regular expressions in search string (supported only for the text search)
"""

SEARCH_NOBRK = _ida_search.SEARCH_NOBRK
r"""
do not test if the user clicked cancel to interrupt the search
"""

SEARCH_NOSHOW = _ida_search.SEARCH_NOSHOW
r"""
do not display the search progress/refresh screen
"""

SEARCH_IDENT = _ida_search.SEARCH_IDENT
r"""
search for an identifier (text search). it means that the characters before and
after the match cannot be is_visible_char().
"""

SEARCH_BRK = _ida_search.SEARCH_BRK
r"""
return BADADDR if the search was cancelled.
"""

SEARCH_USE = _ida_search.SEARCH_USE
r"""
find_reg_access: search for a use (read access)
"""

SEARCH_DEF = _ida_search.SEARCH_DEF
r"""
find_reg_access: search for a definition (write access)
"""

SEARCH_USESEL = _ida_search.SEARCH_USESEL
r"""
query the UI for a possible current selection to limit the search to
"""


def search_down(sflag: "int") -> "bool":
    r"""
    search_down(sflag) -> bool
    Is the SEARCH_DOWN bit set?

    @param sflag: (C++: int)
    """
    return _ida_search.search_down(sflag)

def find_error(ea: "ea_t", sflag: "int") -> "int *":
    r"""
    find_error(ea, sflag) -> ea_t
    Find next error or problem.

    @param ea: (C++: ea_t)
    @param sflag: (C++: int)
    """
    return _ida_search.find_error(ea, sflag)

def find_notype(ea: "ea_t", sflag: "int") -> "int *":
    r"""
    find_notype(ea, sflag) -> ea_t
    Find next operand without any type info.

    @param ea: (C++: ea_t)
    @param sflag: (C++: int)
    """
    return _ida_search.find_notype(ea, sflag)

def find_unknown(ea: "ea_t", sflag: "int") -> "ea_t":
    r"""
    find_unknown(ea, sflag) -> ea_t
    Find next unexplored address.

    @param ea: (C++: ea_t)
    @param sflag: (C++: int)
    """
    return _ida_search.find_unknown(ea, sflag)

def find_defined(ea: "ea_t", sflag: "int") -> "ea_t":
    r"""
    find_defined(ea, sflag) -> ea_t
    Find next ea that is the start of an instruction or data.

    @param ea: (C++: ea_t)
    @param sflag: (C++: int)
    """
    return _ida_search.find_defined(ea, sflag)

def find_suspop(ea: "ea_t", sflag: "int") -> "int *":
    r"""
    find_suspop(ea, sflag) -> ea_t
    Find next suspicious operand.

    @param ea: (C++: ea_t)
    @param sflag: (C++: int)
    """
    return _ida_search.find_suspop(ea, sflag)

def find_data(ea: "ea_t", sflag: "int") -> "ea_t":
    r"""
    find_data(ea, sflag) -> ea_t
    Find next data address.

    @param ea: (C++: ea_t)
    @param sflag: (C++: int)
    """
    return _ida_search.find_data(ea, sflag)

def find_code(ea: "ea_t", sflag: "int") -> "ea_t":
    r"""
    find_code(ea, sflag) -> ea_t
    Find next code address.

    @param ea: (C++: ea_t)
    @param sflag: (C++: int)
    """
    return _ida_search.find_code(ea, sflag)

def find_not_func(ea: "ea_t", sflag: "int") -> "ea_t":
    r"""
    find_not_func(ea, sflag) -> ea_t
    Find next code address that does not belong to a function.

    @param ea: (C++: ea_t)
    @param sflag: (C++: int)
    """
    return _ida_search.find_not_func(ea, sflag)

def find_imm(ea: "ea_t", sflag: "int", search_value: "uval_t") -> "int *":
    r"""
    find_imm(ea, sflag, search_value) -> ea_t
    Find next immediate operand with the given value.

    @param ea: (C++: ea_t)
    @param sflag: (C++: int)
    @param search_value: (C++: uval_t)
    """
    return _ida_search.find_imm(ea, sflag, search_value)

def find_text(start_ea: "ea_t", y: "int", x: "int", ustr: "char const *", sflag: "int") -> "ea_t":
    r"""
    find_text(start_ea, y, x, ustr, sflag) -> ea_t
    See search()

    @param start_ea: (C++: ea_t)
    @param y: (C++: int)
    @param x: (C++: int)
    @param ustr: (C++: const char *) char const *
    @param sflag: (C++: int)
    """
    return _ida_search.find_text(start_ea, y, x, ustr, sflag)

def find_reg_access(out: "reg_access_t", start_ea: "ea_t", end_ea: "ea_t", regname: "char const *", sflag: "int") -> "ea_t":
    r"""
    find_reg_access(out, start_ea, end_ea, regname, sflag) -> ea_t
    Find access to a register.

    @param out: (C++: struct reg_access_t *) pointer to the output buffer. must be non-null. upon success
                contains info about the found register. upon failed search for a
                read access out->range contains the info about the non-redefined
                parts of the register.
    @param start_ea: (C++: ea_t) starting address
    @param end_ea: (C++: ea_t) ending address. BADADDR means that the end limit is missing.
                   otherwise, if the search direction is SEARCH_UP, END_EA must be
                   lower than START_EA.
    @param regname: (C++: const char *) the register to search for.
    @param sflag: (C++: int) combination of Search flags bits.
    @note: This function does not care about the control flow and probes all
           instructions in the specified range, starting from START_EA. Only direct
           references to registers are detected. Function calls and system traps are
           ignored.
    @return: the found address. BADADDR if not found or error.
    """
    return _ida_search.find_reg_access(out, start_ea, end_ea, regname, sflag)


