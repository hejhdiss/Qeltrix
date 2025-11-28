#!/usr/bin/env python3
"""
Qeltrix (.qltx) - Content-derived, parallel, streaming obfuscation container (PoC)

Copyright (c) 2025 @hejhdiss(Muhammed Shafin P)
All rights reserved.
Licensed under GPLv3.
"""
import sys
import subprocess
import os
import struct
from typing import List, Tuple, Optional
import copy

# --- Qeltrix Header Detection Constants ---
MAGIC = b"QLTX"
HEADER_SIZE = 8

def detect_qeltrix_version(filepath: str) -> Optional[str]:
    try:
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None

        with open(filepath, "rb") as f:
            header = f.read(HEADER_SIZE)

        if len(header) < HEADER_SIZE or header[:4] != MAGIC:
            return None 

        # CRITICAL FIX: Change from big-endian (>) to little-endian (<) 
        # to match how your backend scripts are saving the version.
        version_num = struct.unpack('<I', header[4:])[0] 
        
        # Corrected the single '=' assignment operator to '==' comparison
        if version_num == 5:
            return 'v5'
        elif version_num == 4:
            return 'v4'
        elif version_num == 3:
            return 'v3' 
        elif version_num == 2:
            return 'v2' 
        elif version_num == 1:
            return 'v1' 
        else:
            return None

    except Exception:
        return None

# The function now accepts the pre-determined version and passes the clean args through.
def get_script_and_version_for_pack(version_arg: str, args_to_pass: List[str]) -> Tuple[str, str, List[str]]:
    """
    Determines the target script and version for the 'pack' command based on 
    the mandatory version_arg supplied before the command.
    
    Returns (script_file, version, backend_args_list).
    """
    # The args_to_pass list is already clean (does not contain -v)
    try:
        # Determine routing based on the explicit version number
        if version_arg == '5':
            return 'qeltrix-5.py', 'v5', args_to_pass
        elif version_arg == '4':
            return 'qeltrix-4.py', 'v4', args_to_pass
        elif version_arg == '3':
            return 'qeltrix-3.py', 'v3', args_to_pass
        # V1 and V2 are routed to the shared backward-compatible script
        elif version_arg == '2' :
            return 'qeltrix-2.py', 'v2', args_to_pass
        elif version_arg == '1':
            return 'qeltrix.py' , 'v1' ,args_to_pass
        else:
            raise ValueError(f"Invalid Qeltrix version number specified: {version_arg}")

    except ValueError as e:
        raise e
    except Exception:
        raise ValueError(f"Error processing specified version '{version_arg}'.")
    

def get_script_and_version_for_decode(command: str, qltx_file: str) -> Tuple[str, str]:
    """
    Determines the target script and version for 'unpack' or 'seek' by
    reading the version from the file header.
    """
    
    version = detect_qeltrix_version(qltx_file)
    
    if not version:
        raise ValueError(f"Input file '{qltx_file}' is not a valid Qeltrix container or version is unsupported.")

    # --- ROUTING LOGIC ---
    if version == 'v5':
        return 'qeltrix-5.py', version
    if version == 'v3':
        return 'qeltrix-3.py', version
    if version == 'v4':
        return 'qeltrix-4.py' ,version
    
    # V1 and V2 files MUST be routed to qeltrix-2.py for backwards compatibility.
    if version == 'v2' or version == 'v1':
        return 'qeltrix-2.py', version 
        
    raise ValueError(f"Unsupported Qeltrix version '{version}' detected in file.")

# === MAIN EXECUTION LOGIC ===

def main():
    
    # Minimum arguments are 3 for unpack/seek: python, qltx.py, <cmd>, <file>
    if len(sys.argv) < 3:
        print("Usage for packing: python qltx.py -v <version_num> pack [args...]", file=sys.stderr)
        print("Usage for decoding: python qltx.py <unpack|seek> <qltx_file> [args...]", file=sys.stderr)
        sys.exit(1)

    version_arg = None
    
    try:
        script_file = None
        version = None
        
        # --- Determine CLI structure based on first argument ---
        if sys.argv[1].lower() == "-v":
            # Structure 1: Mandatory for 'pack' -> qltx.py -v <version_num> <command> [args...]
            
            if len(sys.argv) < 4:
                raise ValueError("Missing command after version flag.")
            
            version_arg = sys.argv[2]
            command = sys.argv[3].lower()
            # Arguments for the backend script, starting after the command
            args_to_pass = sys.argv[4:] 
            
            if command != "pack":
                raise ValueError(f"The -v flag is only required and accepted before the 'pack' command. Use 'qltx.py {command} ...' instead.")
            
            # Proceed with pack logic
            full_args_for_subproc = [command] 
            script_file, version, backend_args = get_script_and_version_for_pack(version_arg, args_to_pass)
            full_args_for_subproc.extend(backend_args)

        else:
            # Structure 2: Optional for decode -> qltx.py <command> [args...]
            
            command = sys.argv[1].lower()
            # Arguments for the backend script, starting after the command
            args_to_pass = sys.argv[2:] 
            
            if command == "pack":
                # User tried to pack without the mandatory -v flag
                raise ValueError(f"The 'pack' command requires a version flag: Usage: python qltx.py -v <version_num> pack [args...]")
            
            if command in ["unpack", "seek"]:
                if len(args_to_pass) < 1:
                    raise ValueError(f"Command '{command}' requires an input file.")
                
                # --- NEW LOGIC: Find the qltx_file path for version detection ---
                # The dispatcher must read the input file's header to determine the version (V1-V5)
                # and route the command correctly. Newer backend scripts (V5) use the --input-file
                # flag, so we must search for that flag and its value in the arguments list.
                
                qltx_file = None
                try:
                    # Try to find the file path passed using the standard flag for newer versions
                    input_file_index = args_to_pass.index('--input-file')
                    if input_file_index + 1 < len(args_to_pass):
                        qltx_file = args_to_pass[input_file_index + 1]
                    else:
                        raise ValueError(f"Flag '--input-file' requires a file path argument.")
                except ValueError:
                    # Fallback for older versions that use positional argument
                    # This handles: 'qltx.py unpack archive.qltx ...'
                    qltx_file = args_to_pass[0]
                
                if not qltx_file:
                    raise ValueError(f"Could not determine the input file path for '{command}' command.")
                # --- END NEW LOGIC ---

        # --- Shared Dispatch Logic ---
        script_file, version = get_script_and_version_for_decode(command, qltx_file)
        script_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_file)
        full_args_for_subproc = [command] + args_to_pass

        if not os.path.exists(script_file_path):
            raise FileNotFoundError(f"Backend script '{script_file}' not found.")
            
        # Construct the final command: python <script> <command> <args...>
        full_command = [sys.executable, script_file_path] + full_args_for_subproc
        
        print(f"--- Qeltrix Dispatcher ---\nCommand: {command.upper()}, Detected/Target Version: {version.upper()}\nDispatching to: {os.path.basename(script_file)}\n--------------------------", file=sys.stderr)

        result = subprocess.run(full_command, check=False)
        sys.exit(result.returncode)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
if __name__ == "__main__":
    main()
