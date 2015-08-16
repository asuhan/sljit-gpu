# sljit for GPUs

## Goal

Make PCRE run (well) on GPUs.

## Approach

Keep the regex translator as close to the original form as possible and add a backend to sljit which can target GPUs.
Since there's no backwards compatibility at the binary level for GPUs, we're stuck with LLVM, for better or worse.

## Status

Most of the instructions required by the regex translator are in place and most of sljit tests pass on x64 with this backend.
We're only using x64 as a validation step. The LLVM IR we generate should run fine on the GPUs except for the overflow intrinsics.
We currently rely on signed / unsigned overflow intrinsics to implement the sljit flags, which are the building blocks for
implementing control flow in sljit. The regex translator only relies on control flow and doesn't actually care about flags.
We'll add a custom LLVM pass to recognize the control flow patterns and replace flags usage with idiomatic LLVM control flow
generation in order to unblock running on GPUs. Registers are implemented as alloca's for simplicity, which means we'll
need to enable the SROA optimization pass for performance. Control flow is implemented through continuations and it'll also
need some optimization work for competitive performance.

This project doesn't include any parallelization changes yet (but they will land), which are crucial for performance on GPUs;
current focus is on correctness.

## Non-goals

Replacing (or improving) any of the current backends is a non-goal. It's highly unlikely we'll invest a lot
of effort into features which are not fundamentally required by the regex engine (floating point, self-modifying code, fast calls). We also assume that the strings are already in the GPU memory and stored contiguously;
using GPUs as an "offload engine" over PCI Express is a non-goal.

## Contributing

Pull requests are warmly welcomed and will be promptly reviewed. Fixes and improvements to the features required by the regex
engine are preferred, but any quality contributions will be accepted.
