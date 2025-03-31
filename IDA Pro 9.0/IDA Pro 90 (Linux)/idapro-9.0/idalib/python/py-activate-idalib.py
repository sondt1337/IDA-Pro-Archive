#!/usr/bin/env python3
import argparse
import platform
import os
from pathlib import Path
import site

# Parse input arguments
parser=argparse.ArgumentParser(description="IDA Python Library setup utility")
parser.add_argument("-d", "--ida-install-dir", 
                    help="IDA installation directory to be used by ida Python library", 
                    type=str, 
                    required=False, 
                    default= None)
args=parser.parse_args()


platform_str = platform.system()

if platform_str == "Windows":
    libname = "idalib64.dll"
elif platform_str == "Linux":
    libname = "libidalib64.so"
elif platform_str == "Darwin":
    libname = "libidalib64.dylib"
else:
    raise Exception(f"Unknown platform {platform_str}")
  

def is_valid_ida_dir(dir:str)->bool:
  """check if a directory looks like a valid IDA installation directory"""
  ida_install_dir = Path(dir)
  return (ida_install_dir / "ida.hlp").is_file() and (ida_install_dir / libname).is_file()

# Check the IDA installation direcory
install_dir = args.ida_install_dir

# Try searching for ida install dir by script location
if install_dir is None:
  install_dir = str(Path(__file__).parent.parent)
  if not is_valid_ida_dir(install_dir):
    install_dir = str(Path(install_dir).parent)
   
if not is_valid_ida_dir(install_dir):
  print(f"The specified IDA installation directory {install_dir} is invalid. Please specify a valid IDA installation directory")
  exit()


print(f"Setting up IDA library Python module using IDA installation directory {install_dir}")

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
print(f"Identified IDA library Python module location {dir_path}")

simlink_dir = str(dir_path / "bin")
print(f"Creating symlink: {install_dir} => {simlink_dir}")


# Attempt removal, a second run whould overwrite the simlink, user may want to switch the ida installation
try:
  os.remove(simlink_dir)
except:
  pass

# Create the simlink
try:
  os.symlink(install_dir, simlink_dir, True)
except Exception as e:
  print(f"Error tryong to create symbolic link, error {e}")