# BCC/eBPF and GDB profilers for PHP.

## BCC
`bcc_blkio.py` and `bcc_cpu.py` are scripts that utilize BCC/eBPF on CentOS 7 to profile PHP 7.4 applications.
I have no idea what happens when these scripts are used with PHP 8 and JIT.
CentOS 7 is not a requirement per-se, yet the scripts are written with CentOS 7 in mind. To support more recent distros, one might need to figure out how to access the `bcc` Python module.

`bcc_blkio.py` attaches to `block:block_rq_insert` to collect the amount of data read and written by the PHP process from the disk.
This is not the right way to collect I/O utilization, given the potential difference between sequential and random I/O, but it definitely shows something.

`bcc_cpu.py` performs on-CPU time profiling (in a way similar to `perf`).

Both scripts emit collapsed stack traces to be processed by `flamegraph`.

Overhead of these scripts was not measured, but it is expected to be low/negligible.

## GDB
`gdb/profiler.go` is a profiler that utilizes GDB/MI to collect C and PHP stack traces of PHP processes.
The script requires having PHP interpreter debug symbols installed and accessible by GDB.

The script output has to be processed via `gdb/php-gdb.ipynb` Jupyter notebook.
The notebook output should be located at `<path>.stack` and can be processed by `flamegraph`. The output is an attempt to re-create a C and PHP stack trace together in the same stack (atm, it either puts PHP stack after C stack or, in case PHP code called some C code, puts PHP code between two C stacks).

## Summary
Both scripts were tested only on CentOS 7 with PHP 7.4 on a console PHP application.
They worked and produced meaningful (non-shareable :) ) results in my scenario, yet no attempts were made to test them in other scenarios.
