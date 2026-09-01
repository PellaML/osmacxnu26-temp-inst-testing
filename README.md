# osmacxnu26-temp-inst-testing

Temporary measurement harness. Exists only to run a userspace probe on GitHub's
Apple silicon runners and print the results.

## What it does

`probe/darwin_probe.c` reads, from the machine it runs on:

- the **commpage** (`0x0000000FFFFFC000`) — named fields plus a raw hexdump,
  including the 20-byte region at `+0x10C`–`+0x11F` that the public
  `osfmk/arm/cpu_capabilities.h` leaves undefined;
- the **`SPRR_PERM_EL0`** system register (`S3_6_C15_C1_5`) and its alternative
  encoding (`S3_4_C15_C2_7`), on either side of a `pthread_jit_write_protect_np()`
  flip, to establish which commpage word corresponds to which permission state;
- the **identity sysctls** (`hw.machine`, `hw.model`, `hw.target`, `hw.product`,
  `hw.cputype`, `hw.cpusubtype`, `hw.cpufamily`, …);
- **`hw.optional.arm.caps`**, including a length probe and a deliberately
  oversized `oldlen`, to confirm the buffer length and check nothing is written
  past the reported length;
- the per-feature `hw.optional.arm.FEAT_*` sysctls, to cross-check the three
  places the same capability is exposed.

Every read is guarded by `SIGBUS`/`SIGSEGV`/`SIGILL` handlers, so an
unreadable address or a trapping system register prints `<fault>` instead of
killing the run.

## What it does not do

- It contains **no Apple code** and copies none. It only prints values that any
  process can read about its own machine.
- It does not modify the runner, install anything, or reach the network.
- It is not a general-purpose compute job — it is a measurement of the platform
  the associated project targets.

## Running it

Runs automatically on push, or via **Actions → darwin-probe → Run workflow**.
Results appear in the job log and as artifacts.

## Status

Temporary. Delete when the measurements have been folded back into the main
project's notes.
