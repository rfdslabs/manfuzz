"""
  __  __           _____             _____            
 |  \/  |         |  __ \           |  __ \           
 | \  / | ___  ___| |__) |__ _ _   _| |  | | ___ _ __  
 | |\/| |/ _ \/ __|  _  // _` | | | | |  | |/ _ \ '_ \ 
 | |  | |  __/\__ \ | \ \ (_| | |_| | |__| |  __/ | | |
 |_|  |_|\___||___/_|  \_\__,_|\__, |_____/ \___|_| |_|
                                __/ |                 
                               |___/                  
                               
 ManFuzz - UNIX Binary Fuzzing Tool - This is was maded in 2004! Good gold years of simple buffers! 
Still working today 2024!

 Author: @rfdslabs
 License: MIT License

 Description: This script fuzzes UNIX binaries by leveraging their manual pages, generating
              potential fuzzing payloads to discover vulnerabilities such as buffer overflows,
              format string exploits, stack smashing, and other possible flaws.

 Payloads: 
    - Buffer overflow strings ('A', 'B', 'C' overflow patterns)
    - Format string exploits ('%n', '%x', '%s', '%p')
    - Stack smashing payloads, EIP overwrites, NOP sleds
    - Various ASCII and hex patterns for memory corruption
    
 Usage: 
    - python3 manfuzz.py /path/to/binary
    - python3 manfuzz.py /path/to/directory

"""


import sys
import os
import re
import random
import time
import signal
import subprocess
import concurrent.futures
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(filename='fuzz_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

# Payloads to use in fuzzing
PAYLOADS = [
    'A' * 7900,  # Basic overflow with 'A'
    'B' * 8000,  # Slightly larger basic overflow with 'B'
    'C' * 9000,  # Even larger basic overflow with 'C'
    'D' * 10000, # Large overflow with 'D'
    '1' * 7900,  # Numeric overflow
    '2' * 8000,  # Slightly larger numeric overflow
    '%n' * 1000,  # Format string exploit
    '%x' * 1000,  # Hexadecimal format string exploit
    '%s' * 1000,  # String format exploit
    '%p' * 1000,  # Pointer format exploit
    '%c%s%d%f' * 250,  # Mixed format string exploit
    'A' * 4096 + '\xef\xbe\xad\xde',  # Classic EIP overwrite pattern
    'A' * 4100 + '\x42' * 4,  # Simple stack smashing with "B" to overflow the return address
    '\x41\x41\x41\x41' * 2000,  # ASCII hex patterns for potential code execution
    '\x90' * 1000 + '\xcc' * 1000,  # NOP sled followed by int3 (breakpoint)
    'A' * 8000 + '\x00',  # Overflow ending with null byte
    'A' * 7998 + '\r\n',  # Overflow with carriage return and newline
    'A' * 7998 + '\x0a\x0d',  # Overflow with newline and carriage return (reverse)
    'A' * 7996 + '\x00\x00\x00\x00',  # Overflow with null DWORD
    'A' * 7996 + '\x01\x01\x01\x01',  # Overflow with non-null DWORD
    'A' * 7996 + '\x01\x02\x03\x04',  # Overflow with incrementing DWORD
    'A' * 4096 + '\xde\xad\xbe\xef' * 100,  # Repeated EIP overwrite pattern
    'A' * 5000 + '\xf0\x0d\xba\xbe',  # Another EIP overwrite with a different pattern
    'A' * 7996 + '\xff\xff\xff\xff',  # Overflow with maximum DWORD value
    'A' * 7996 + '\x7f\xff\xff\xff',  # Overflow with maximum signed DWORD value
    'A' * 8000 + '\x7f',  # Overflow with boundary value
    'A' * 8000 + '\x80',  # Overflow with negative boundary value
    'A' * 7996 + '\x7e\x7e\x7e\x7e',  # Overflow with tilde (~) pattern
    'A' * 4096 + '\x0a' * 4096,  # Overflow with newline padding
    'A' * 4096 + '\x20' * 4096,  # Overflow with space padding
    '\x41\x42\x43\x44' * 2000,  # ABCD pattern for offset identification
    'A' * 1000 + '\x00' + 'B' * 1000,  # Overflow with null byte separator
    'A' * 4000 + '\xff' * 4000,  # Mixed pattern with maximum byte value
]


# Number of threads to use for parallel processing
MAX_WORKERS = 4

# Output directory for logs
OUTPUT_DIR = Path('./fuzz_logs')
OUTPUT_DIR.mkdir(exist_ok=True)

def detect_man():
    # Since macOS does not have the -c or --catman options, we just return the basic man command
    return 'man %s'

def read_man(man, cmd):
    p = subprocess.Popen(man % cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    txt = p.stdout.read().decode('utf-8')
    txt = re.sub(r'_\x08([^_])', r'\1', txt)  # Strip underlines.
    if len(txt) == 0:
        return []
    # Interpret bold.
    bold = False  # state
    newtxt = ''
    i = 0
    while i < len(txt) - 1:
        if bold:
            if txt[i+1] == '\x08':
                newtxt += txt[i]
                i += 3
            else:
                newtxt += '\x02'  # end bold tag
                bold = False
        else:
            if txt[i+1] == '\x08':
                newtxt += '\x01'  # start bold tag
                bold = True
            else:
                newtxt += txt[i]
                i += 1
    newtxt += txt[-1]
    return [x.strip() for x in newtxt.split('\n')]

def gather_info(lines):
    synopsis = False   # state
    usages = []
    options = []
    for line in lines:
        if synopsis:
            if line == '\x01DESCRIPTION\x02':
                synopsis = False
            else:
                if len(line) > 0:
                    if (line[0] != '\x01') and (len(usages) > 0):
                        usages[-1] += ' '+line
                    else:
                        usages.append(line)
        else:
            if line == '\x01SYNOPSIS\x02':
                synopsis = True
            else:
                for regex in (r'^-([A-Za-z0-9]+)', r'\x01-([A-Za-z0-9]+)'):
                    m = re.search(regex, line)
                    if m:
                        for x in m.group(1):
                            options.append('-'+x)
                for regex in (r'^--([^,; \t\x02=]+)', r'\x01--([^,; \t\x02=]+)'):
                    m = re.search(regex, line)
                    if m:
                        options.append('--'+m.group(1))
                for regex in (r'^\x01([a-z0-9][A-Za-z0-9_-]*)\x02', ):
                    m = re.search(regex, line)
                    if m:
                        options.append(m.group(1))
    return (usages, list(set(options)))

def usage_to_fuzz_fmt(usage):
    usage = usage.replace('[','').replace(']','').replace('|','')
    bold = False
    fmt = ''
    for c in usage:
        if c == '\x01':
            bold = True
        elif c == '\x02':
            bold = False
        elif bold:
            fmt += c
        elif c in (' ', '\t'):
            fmt += c
        else:
            fmt += '\x03'
    fmt = re.sub(r'\x03+', ' \x03 ', fmt)
    fmt = re.sub(r'\s+', ' ', fmt)
    return fmt

def options_to_fuzz_fmt(prog, options):
    fmt = prog+' '
    for option in options:
        if option[:2] == '--':
            fmt += option+'=\x03 '
        else:
            fmt += option+' \x03 '
    return fmt

def exec_and_log(cmd):
    cmd = cmd.strip().split(' ')
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
    p.stdin.write(b'\n'*50)
    p.stdin.close()
    time.sleep(0.01)
    os.kill(p.pid, signal.SIGKILL)
    if p.wait() == -signal.SIGSEGV:
        msg = '** SIGSEGV on %s\n' % repr(cmd)
        print(msg)
        log_file = OUTPUT_DIR / f'{os.path.basename(cmd[0])}_log.txt'
        with open(log_file, 'a') as f:
            f.write(msg)
        logging.info(msg)

def do_try(fmt):
    for payload in PAYLOADS:
        try: 
            exec_and_log(fmt.replace('\x03', payload))
        except Exception as e:
            logging.error(f"Error during execution: {e}")

def fuzz_binary(prog):
    print(f'Fuzzing -> {prog}')
    man = detect_man()
    usages, options = gather_info(read_man(man, os.path.basename(prog)))
    
    # Try usage suggestions from synopsis
    for fmt in set([usage_to_fuzz_fmt(usage) for usage in usages]):
        do_try(fmt)
    
    # Try combinations of one option with an argument
    for opt in options:
        do_try(options_to_fuzz_fmt(prog, (opt,)))
    
    # Try combinations of two options together with arguments
    for opt1 in random.sample(options, min(5, len(options))):
        for opt2 in random.sample(options, min(5, len(options))):
            do_try(options_to_fuzz_fmt(prog, (opt1, opt2)))

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <directory or binary>")
        sys.exit(1)
    
    path = sys.argv[1]
    
    if os.path.isdir(path):
        binaries = [os.path.join(path, f) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(fuzz_binary, binaries)
    elif os.path.isfile(path):
        fuzz_binary(path)
    else:
        print(f"Error: {path} is not a valid directory or file.")
        sys.exit(1)

if __name__ == '__main__':
    main()

