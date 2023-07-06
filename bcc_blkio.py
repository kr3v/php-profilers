#!/usr/bin/python2.7
# This script uses 'bcc' from official repos, which requires Python 2.7.

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig

# https://github.com/adsr/phpspy
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

typedef struct _zend_executor_globals_74 zend_executor_globals_74;
typedef struct _zend_execute_data_74     zend_execute_data_74;
typedef struct _zend_op_array_74         zend_op_array_74;
typedef union  _zend_function_74         zend_function_74;
typedef struct _zend_class_entry_74      zend_class_entry_74;
typedef struct _zend_string_74           zend_string_74;
typedef struct _zend_op_74               zend_op_74;
typedef struct _sapi_request_info_74     sapi_request_info_74;
typedef struct _sapi_globals_struct_74   sapi_globals_struct_74;
typedef union  _zend_value_74            zend_value_74;
typedef struct _zval_74                  zval_74;
typedef struct _Bucket_74                Bucket_74;
typedef struct _zend_array_74            zend_array_74;
typedef struct _zend_alloc_globals_74    zend_alloc_globals_74;
typedef struct _zend_mm_heap_74          zend_mm_heap_74;

/* Assumes 8-byte pointers */
                                                    /* offset   length */
struct __attribute__((__packed__)) _zend_array_74 {
    uint8_t                 pad0[12];               /* 0        +12 */
    uint32_t                nTableMask;             /* 12       +4 */
    Bucket_74               *arData;                /* 16       +8 */
    uint32_t                nNumUsed;               /* 24       +4 */
    uint32_t                nNumOfElements;         /* 28       +4 */
    uint32_t                nTableSize;             /* 32       +4 */
};

struct __attribute__((__packed__)) _zend_executor_globals_74 {
    uint8_t                 pad0[304];              /* 0        +304 */
    zend_array_74           symbol_table;           /* 304      +36 */
    uint8_t                 pad1[148];              /* 340      +148 */
    zend_execute_data_74    *current_execute_data;  /* 488      +8 */
};

struct __attribute__((__packed__)) _zend_execute_data_74 {
    zend_op_74              *opline;                /* 0        +8 */
    uint8_t                 pad0[16];               /* 8        +16 */
    zend_function_74        *func;                  /* 24       +8 */
    uint8_t                 pad1[16];               /* 32       +16 */
    zend_execute_data_74    *prev_execute_data;     /* 48       +8 */
    zend_array_74           *symbol_table;          /* 56       +8 */
};

struct __attribute__((__packed__)) _zend_op_array_74 {
    uint8_t                 pad0[52];               /* 0        +52 */
    int                     last_var;               /* 52       +4 */
    uint8_t                 pad1[40];               /* 56       +40 */
    zend_string_74          **vars;                 /* 96       +8 */
    uint8_t                 pad2[32];               /* 104      +32 */
    zend_string_74          *filename;              /* 136      +8 */
    uint32_t                line_start;             /* 144      +4 */
};

union __attribute__((__packed__)) _zend_function_74 {
    uint8_t                 type;                   /* 0        +8 */
    struct {
        uint8_t             pad0[8];                /* 0        +8 */
        zend_string_74      *function_name;         /* 8        +8 */
        zend_class_entry_74 *scope;                 /* 16       +8 */
    } common;
    // zend_op_array_74        op_array;               /* 0        +148 */
};

struct __attribute__((__packed__)) _zend_class_entry_74 {
    uint8_t                 pad0[8];                /* 0        +8 */
    zend_string_74          *name;                  /* 8        +8 */
};

struct __attribute__((__packed__)) _zend_string_74 {
    uint8_t                 pad0[16];               /* 0        +16 */
    size_t                  len;                    /* 16       +8 */
    char                    val[1];                 /* 24       +8 */
};

struct __attribute__((__packed__)) _zend_op_74 {
    uint8_t                 pad0[24];               /* 0        +24 */
    uint32_t                lineno;                 /* 24       +4 */
};

union __attribute__((__packed__)) _zend_value_74 {
    long                    lval;                   /* 0        +8 */
    double                  dval;                   /* 0        +8 */
    zend_string_74          *str;                   /* 0        +8 */
    zend_array_74           *arr;                   /* 0        +8 */
};

struct __attribute__((__packed__)) _zval_74 {
    zend_value_74           value;                  /* 0        +8 */
    union {
        struct {
            uint8_t         type;                   /* 8        +1 */
            uint8_t         pad0[3];                /* 9        +3 */
        } v;
    } u1;
    union {
        uint32_t next;                              /* 12       +4 */
    } u2;
};

struct __attribute__((__packed__)) _Bucket_74 {
    zval_74                 val;                    /* 0        +16 */
    uint64_t                h;                      /* 16       +8 */
    zend_string_74          *key;                   /* 24       +32 */
};

struct __attribute__((__packed__)) _zend_alloc_globals_74 {
    zend_mm_heap_74         *mm_heap;               /* 0        +8 */
};

struct __attribute__((__packed__)) _zend_mm_heap_74 {
    uint8_t                 pad0[16];               /* 0        +16 */
    size_t                  size;                   /* 16       +8 */
    size_t                  peak;                   /* 24       +8 */
};

#define MAX_ARG 32

struct php_stack {
    int count;
    int offset;

    int arg1;
    int src;

    char buff[32 * MAX_ARG];
};

BPF_PERF_OUTPUT(php_stacks);
BPF_PERCPU_ARRAY(php_stack_a, struct php_stack, 1);

static int count(void *ctx, int sz, int src) {
    int key = 0;
    struct php_stack* s = php_stack_a.lookup(&key);
    if (s == 0) { return 0; }

    u32 pid = bpf_get_current_pid_tgid();
    if (pid != INTERESTING_PID) {
        return 0;
    }

    void*                    d_addr;
    zend_execute_data_74     d;
    zend_function_74         f;
    zend_string_74           n;

    s->count = 0;
    s->arg1 = sz;

    s->buff[0] = '0' + src;
    s->buff[1] = ';';
    int offset = 2;

    bpf_probe_read(&d_addr, sizeof(d_addr), 0xc1df00+488);
    #pragma unroll
    for (int i = 0; i < MAX_ARG - 1; i++) {
        if (d_addr == 0) { break; }
        bpf_probe_read(&d, sizeof(d), d_addr);
        d_addr = d.prev_execute_data;
        if (d.func == 0) { continue; }
        bpf_probe_read(&f, sizeof(f), d.func);
        if (f.common.function_name == 0) { continue; }
        offset += bpf_probe_read_str(s->buff+offset, 32, ((char*)f.common.function_name)+24);
        s->buff[offset-1] = ';';
        s->count++;
    }
    s->buff[offset] = 0;
    s->offset = offset;

    php_stacks.perf_submit(ctx, s, sizeof(struct php_stack));
    return 0;
}

static int count_alloc(struct pt_regs *ctx, int src) {
    count(ctx, (int) PT_REGS_PARM1(ctx), src);
}

int count_emalloc(struct pt_regs *ctx) {
    count_alloc(ctx, 1);
}

int count_malloc(struct pt_regs *ctx) {
    count_alloc(ctx, 2);
}

TRACEPOINT_PROBE(block, block_rq_insert) {
    count(args, args->nr_sector, 3);
}
"""

import argparse

parser = argparse.ArgumentParser(description='')
parser.add_argument('--pid', help='attach to pid')
parser.add_argument('--output', help='output path')

args = parser.parse_args()

# initialize BPF & perf_events
b = BPF(text=bpf_text.replace("INTERESTING_PID", args.pid.strip()))
# b.attach_perf_event(ev_type=PerfType.SOFTWARE,
#                     ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
#                     sample_freq=99, cpu=-1, pid=int(args.pid.strip()))
# b.attach_uprobe(name="/usr/bin/php", sym="_emalloc", fn_name="count_emalloc", pid=int(args.pid.strip()))
# b.attach_uprobe(name="/lib64/libc-2.17.so", sym="malloc", fn_name="count_malloc", pid=int(args.pid.strip()))
# b.attach_tracepoint(tp="block:block_rq_insert", fn_name="count_blk_rq_issue")

php_stacks = b.get_table("php_stacks")

d = {}

def emit_items(e):
    return e.buff[:e.offset]

def print_event(ctx, data, size):
    e = php_stacks.event(data)
    k = emit_items(e)
    c = e.arg1
    d[k] = d.setdefault(k, 0) + c

# loop with callback to print_event
php_stacks.open_perf_buffer(print_event)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt, KeyError:
        break

with open(args.output, mode='w') as f:
    for k, v in d.items():
        f.write(k + '\t' + str(v) + '\n')
exit()
