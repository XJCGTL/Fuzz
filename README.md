# Fuzz

Template-based test-case generator for **Spectre-v1 (conditional-branch
misprediction)** on the **RISC-V (RV64GC)** architecture.

## Files

| File | Description |
|---|---|
| `condBranchMispred.c` | Original RISC-V Spectre PoC (fixed template reference) |
| `fuzz_gen.py` | Test-case generator – randomises the transient execution block |
| `encoding.h` | Attack constants (`ATTACK_SAME_ROUNDS`, `TRAIN_TIMES`, `ROUNDS`) |
| `cache.h` | Cache-helper declarations (`flushCache`, `ProbeCache`, `High_two_result`) |

## How it works

`fuzz_gen.py` keeps the following parts of the victim fixed across all
generated test cases:

1. The slow floating-point dependency chain that creates the misprediction
   window.
2. The bounds-check branch (`bltu a5, a1, 1f`).
3. The main attack harness in `main()`.

It **randomly replaces only the transient execution block** — the instructions
that execute speculatively after the bounds check — using one of several
strategies:

| Strategy | Description |
|---|---|
| `standard` | Original gadget (shift by 6, access `array2[secret*64]`) |
| `varied_shift` | Same structure, randomised cache-stride shift (4–8 bits) |
| `arithmetic` | Random arithmetic/logical transforms on the secret byte before encoding |
| `multi_load` | Two dependent loads from `array1` before the cache-encode step |
| `random_loads` | Extra speculative loads from random registers before the cache-encode |
| `jump_replace` | Injects conditional branches, unconditional `jal`, and indirect `jalr` jumps inside the transient window to probe nested branch-predictor interaction |

## Usage

```bash
# Generate 10 test cases (random strategy mix) into fuzz_cases/
python3 fuzz_gen.py

# Generate 20 cases with a fixed seed for reproducibility
python3 fuzz_gen.py -n 20 -s 42

# Generate cases using one specific strategy
python3 fuzz_gen.py -n 5 --strategy arithmetic

# Custom output directory
python3 fuzz_gen.py -n 10 -o /tmp/spectre_cases

# List all available strategies
python3 fuzz_gen.py --list-strategies
```

## Compiling a generated test case

```bash
riscv64-linux-gnu-gcc -O0 -march=rv64gc \
    -o testcase fuzz_cases/testcase_0000.c cache.c -lm
```

> **Note:** You must supply `cache.c` with implementations of `flushCache`,
> `ProbeCache`, and `High_two_result` suited to your RISC-V target platform.