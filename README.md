# DriverScanner

Windows driver analysis tool that scans `.sys` files for imports of the `ZwTerminateProcess` API from the `ntoskrnl.exe` kernel, identifying potential kernel-mode process termination vectors.
