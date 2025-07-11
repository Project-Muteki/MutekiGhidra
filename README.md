# MutekiGhidra

Deeper Ghidra integration.

## Features

- Kernel image (`xAxxx.ROM`) loader.
- Script to syscall .

## Install

Build with `gradle` and install the built ZIP file with `File -> Install Extensions`.

## Recommended usage 

### Kernel reversing

- Load the kernel image file as a `Besta RTOS Kernel Image`. Do NOT run analysis when prompted.
- Splice the loaded image into read-only and read-write sections by scanning for contiguous trailing `FF`s (will be done automatically by the kernel image loader in the future)
- Extract the syscall shims (`sdklib.dll` and `krnllib.dll`) from the firmware system data partition, and use them with `SyscallLabeler.java` to label.
- Import the known syscall signatures with [muteki-shims](https://github.com/Project-Muteki/muteki-shims?tab=readme-ov-file#integrating-muteki-shims-into-ghidra) and label the syscalls with `Apply Function Data Types`.
- Run analysis.
- Use the script `FindSharedReturnFunctionsScript.java` to fix shared returns.
