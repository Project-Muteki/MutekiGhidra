# MutekiGhidra

Deeper Ghidra integration.

## Features

- Kernel image (`xAxxx.ROM`) and dump loader with architecture detection.
- Script to automatically find kernel syscall handler and label all syscall functions (`SyscallLabeler.java`).

## Install

Build with `gradle` and install the built ZIP file with `File -> Install Extensions`.

## Recommended usage 

### Kernel reversing

- Load the kernel image file as a `Besta RTOS Kernel`. Do NOT run analysis when prompted.
- Splice the loaded image into read-only and read-write sections
  - There isn't a good way of doing this automatically yet. Best one can do is taking a memory dump and comparing it with a clean image file to see what blocks have changed. Although scanning for contiguous `FF`s from the end of a clean image file can sometimes achieve good result.
- Extract the syscall shims (`sdklib.dll` and `krnllib.dll`) from the firmware system data partition, and use them with `SyscallLabeler.java` to label the syscalls.
- Import the currently known syscall signatures from [muteki-shims](https://github.com/Project-Muteki/muteki-shims?tab=readme-ov-file#integrating-muteki-shims-into-ghidra) and type the syscalls with `Apply Function Data Types`.
- Run analysis.
  - Either use the script `FindSharedReturnFunctionsScript.java` to fix shared returns, or enable the `Shared Return Calls` analysis pass during the analysis with `Allow Conditional Jumps` and `Assume Contiguous Functions` options enabled.
