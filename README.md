# ManFuzz

`ManFuzz` is a fuzzing tool designed to test the robustness of UNIX binaries by leveraging their manual (man) pages. It automatically extracts command-line usage patterns and options from binaries' manual pages and injects carefully crafted payloads to identify potential vulnerabilities like buffer overflows, format string exploits, and stack smashing attacks.

## Features

- **Automated Fuzzing**: Uses payloads to fuzz binaries based on their `man` page information.
- **Payload Variety**: Includes payloads for buffer overflows, format string attacks, NOP sleds, EIP overwrites, etc.
- **Multi-threading**: Fuzzes multiple binaries in parallel using Python's `concurrent.futures`.
- **Logging**: Crashes (e.g., `SIGSEGV`) and execution details are logged automatically.
- **No External Dependencies**: Uses Python's built-in libraries.

## Payload Types

The following fuzzing payloads are used:

- **Buffer Overflows**: Overflows with characters such as `A`, `B`, `C`, etc., to test boundary conditions.
- **Format String Exploits**: Payloads such as `%n`, `%x`, `%s`, `%p` to exploit format string vulnerabilities.
- **Stack Smashing**: Overwrites of return addresses using patterns like `\xde\xad\xbe\xef` or `\xf0\x0d\xba\xbe`.
- **NOP Sleds**: Long sequences of `NOP` instructions followed by breakpoint instructions (`\xcc`).
- **Mixed Patterns**: ASCII hex patterns, `ABCD` patterns for identifying offsets, etc.

## Requirements

- Python 3.x
- UNIX-based system with access to `man` pages
- Required Python modules (all included in Python's standard library): `subprocess`, `concurrent.futures`, `re`, `signal`, `logging`, `random`, and `time`.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/rfdslabs/manfuzz.git
    cd manfuzz
    ```

2. Make sure you have Python 3 installed.

3. No additional Python packages are required since all dependencies are part of the standard library.

## Usage

To run `ManFuzz`, you can provide a path to either a single binary file or a directory containing multiple binaries. `ManFuzz` will parse the binaries' manual pages, extract the command-line usage patterns and options, and use them to generate fuzzing payloads.

### Fuzzing a Single Binary

```bash
python3 manfuzz.py /path/to/binary
