import sys
import platform
from pathlib import Path
from ctypes import *
import os
import site

class IdalException(Exception):
    """Unknown platform."""

def find_file(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)
    return None


# get the right filename based on platform
platform_str = platform.system()
platform_custom_err = ""

if platform_str == "Windows":
    name = "idalib64.dll"
elif platform_str == "Linux":
    name = "libidalib64.so"
elif platform_str == "Darwin":
    name = "libidalib64.dylib"
else:
    raise IdalException(f"Unknown platform {platform_str}")

# search for idalib module location   
dir_path=Path(site.getusersitepackages()) / "ida"
if not dir_path.is_dir():
    for site_path in site.getsitepackages():
        dir_path=Path(site_path) / "ida"    
        if dir_path.is_dir():
            break
if not dir_path.is_dir():
    print("You need to install ida python package first by running pip install, see documentation for details")
    exit()

# Locate the "bin" simlink
root_dir = dir_path / "bin"

# Convert the "bin" simlink to real path
root_dir = os.path.realpath(str(root_dir))
                            
# Set the env in order for IDA kernel to be able to locate dependencies
if platform_str == "Windows":
    os.environ["PATH"] = root_dir + os.pathsep + os.environ["PATH"]

os.environ["TVHEADLESS"] = "1"

idalib_path = find_file(name=name, path=root_dir)
if idalib_path is None:
    raise IdalException(f"Could not find {name} in {root_dir}. Please make sure you have an IDA version 9.0 or newer and run py-activate-idalib.py utility shipped with it in order to activate this module.")

if "IDA_IS_INTERACTIVE" in os.environ:
    if os.environ["IDA_IS_INTERACTIVE"] == "1":
        raise IdalException("Cannot run IDALIB in interactive mode.")

# load the library and initialize the kernel
try:
    libida = cdll.LoadLibrary(idalib_path)
except Exception as e:
    print(f"{e}\n{platform_custom_err}\n")
    sys.exit(1)

libida.init_library(0, None)

sys.path.insert(0, str(Path(idalib_path).parent / "python/3/ida_64"))
sys.path.insert(1, str(Path(idalib_path).parent / "python/3"))

def open_database(file_name:str, run_auto_analysis)->int:
  """Open the database specified in file_path argument"""    
  return libida.open_database(file_name.encode(), run_auto_analysis)

def close_database(save = True)->None:
  """Close the current database"""
  return libida.close_database(1 if save else 0)
