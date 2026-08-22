# Benchmarking Wild

## Benchmarking against other linkers

If you decide to benchmark Wild against other linkers, in order to make it a fair comparison, you
should ensure that the other linkers aren't doing work on something that Wild doesn't support. In
particular:

* Wild defaults to `--gc-sections`, so for a fair comparison, that should be passed to all the
  linkers.
* Wild defaults to `-z now`, so best to pass that to all linkers.

## How to benchmark

For the ARM64 macOS Apple-ld64/ld64.lld/Wild replay protocol, including the required workload
manifest and separate wall-time versus resource measurements, see
[`benchmarks/macos-arm64.md`](benchmarks/macos-arm64.md). It intentionally records no benchmark
values until durable capture inputs and complete measurements exist.

## Native Alpine Linux ARM64 Cargo comparison

The Linux counterpart deliberately measures a separate native ELF contract, rather than trying to
reuse the macOS Mach-O and `codesign` runner. It uses `clang` with `lld` as its reference linker,
then replaces only Clang's final `ld.lld` child with Wild. An unmeasured setup copies Cargo,
creates one target, applies the controlled source edit, and captures that real incremental final
link under `-C save-temps`. The reported experiment is only five interleaved replays of the same
captured final-link inputs. Every replay checks an ELF64 little-endian `EM_AARCH64` output and runs
`cargo --version` after removing `LD_*` and `DYLD_*` loader overrides. The workload enables Cargo's
supported `all-static` feature because the native `aarch64-unknown-linux-musl` toolchain must link
a complete static curl/OpenSSL/libgit2 closure. GNU `time -v` supplies separate peak-RSS and CPU
evidence.

This is a native `linux/arm64` Alpine, `all-static` Cargo comparison, not a claim that its absolute
wall times or feature set are comparable with macOS. Run it only on a Docker engine that reports
native `aarch64`/`arm64`; do not benchmark through QEMU emulation. The container source mounts are read-only. Its only durable
state is a bind mount at `~/.cache/wild/linux-aarch64-cargo` for the Cargo registry, Git database,
Wild build, disposable workspaces, and retained JSON reports. The container itself is removed
after every run and the runner removes its raw logs, targets, link outputs, and compiler
temporaries on both success and failure. Docker's regular BuildKit image-layer cache holds the
pinned Alpine toolchain; it does not create a benchmark checkout or target directory under
`~/d`.

```sh
cache_root="$HOME/.cache/wild/linux-aarch64-cargo"
mkdir -p "$cache_root"

docker buildx build --platform linux/arm64 --load \
  --tag wild-bench-alpine-arm64:local \
  --file benchmarks/docker/alpine-aarch64/Dockerfile \
  benchmarks/docker/alpine-aarch64

docker run --rm --platform linux/arm64 \
  --mount type=bind,source="$PWD",target=/work/wild,readonly \
  --mount type=bind,source="$HOME/d/cargo",target=/work/cargo,readonly \
  --mount type=bind,source="$cache_root",target=/cache \
  wild-bench-alpine-arm64:local \
  /work/wild/benchmarks/docker/alpine-aarch64/run-cargo-benchmark.sh
```

The first invocation downloads Rust/Cargo dependencies into that cache mount before unmeasured
capture setup. Later invocations reuse them, and every timed replay is independent of Cargo and
offline. The default is five interleaved final-link replays per linker; set
`WILD_LINUX_LINK_REPETITIONS` or `WILD_LINUX_RESOURCE_LINK_REPETITIONS` on `docker run` only for a
bounded diagnostic screen. Results are written under `$cache_root/benchmarks/`. Pass
`--enforce-goals` to the wrapper only when using the checked-in `1.0x` direct-link gate as a
qualification run.

For repeatable source-build comparisons, use the standard-library Python runner in
[`benchmarks/cargo_link_benchmark.py`](benchmarks/cargo_link_benchmark.py). Current macOS
performance work uses only [`benchmarks/cargo.benchmark.json`](benchmarks/cargo.benchmark.json)
against `~/d/cargo`; the checked-in `e` profiles are retained qualification fixtures, not routine
iteration targets.
It establishes a Cargo baseline, applies one controlled source edit, and replays that incremental
final-link argv directly. Cold Cargo or direct-link measurements are context-only when a legacy
profile still records them; they are not a promotion target for the current macOS work. It records
Apple-ld64/Wild linker-selection evidence and validates the resulting ARM64 Mach-O header, strict
`codesign --verify --strict` evidence, and a checked-in workload runtime smoke check. Runtime
checks execute with all `DYLD_*` environment overrides removed; a cache-hit record is emitted only
after that artifact passes all three validations. It alternates Apple ld64 and Wild by sample to
avoid link-order thermal or filesystem-cache bias, and reports every per-sample Wild/Apple ratio
alongside its median. The runner copies the source checkout to a disposable cache-owned workspace
and never mutates it. It rejects generated paths outside `~/.cache/wild`; its default
`--scratch-root` is `~/.cache/wild/workspaces`, and each run's compiler temporaries live beneath
its own cache-owned artifact root. Rustc deletes the final temporary codegen object
after ordinary links, so each
unmeasured direct-link capture uses a separate disposable `-C save-temps` rebuild. The timed
cold and changed-source Cargo builds share one target and run back-to-back before those capture
rebuilds. With
`--wild-timing-json`, only saved direct Wild replays receive `--time=json`; cold and incremental
Cargo wall-time runs remain command-equivalent between linkers. Matching phase records are retained
under `wild_timing_phases` in the result JSON, and the runner rejects a requested timing capture
that emits no records. The separate resource batch records peak RSS, CPU, final-output bytes, cache
bytes, and observed transient-disk bytes for every configured direct replay. See
`python3 benchmarks/cargo_link_benchmark.py --help` for the required result path and opt-in goal
enforcement. Its default Wild path is `target/aarch64-apple-darwin/dist/wild`; do not use the
unoptimized `ci` profile for a wall-time comparison. Successful runs retain only their JSON report
by default; pass `--keep-artifacts` only when the raw Cargo logs or replay outputs are needed for
diagnosis. The same cleanup policy applies after a failure, so an interrupted or failed experiment
does not silently consume the disk.

Each executable workload manifest has a `runtime` object. Its `arguments` are passed to the produced
ARM64 executable, `expected_exit` defaults to zero, and one of `stdout_contains` or
`stderr_contains` must match; native smoke programs that intentionally print nothing may use
`"output": "exit"`. A non-executable Mach-O artifact such as a proc-macro dylib uses
`"runtime": null` and is still required to pass ARM64 header and strict codesign validation.
Workspace profiles may list multiple `artifacts`; the first is the direct-link replay target and all
listed outputs are validated after each Cargo build. Hashed Cargo outputs can use a glob path, but
it must resolve to exactly one file. This keeps the runtime contract deterministic without requiring
network credentials.

The checked-in source-build matrix includes `cargo.benchmark.json`, `e.benchmark.json`, and
`e-large-rust-lto.benchmark.json` (`e`'s checked-in release profile uses fat LTO and links its
dependency archives). The checked-in qualification fixtures add
`cargo-macho-proc-macro.benchmark.json` and `cargo-macho-native-cpp.benchmark.json`; invoke those
with `--workspace wild/tests/cargo_macho_qualification` and
`--workspace wild/tests/cargo_macho_real_corpus`, respectively. The runner's `--workspace` argument
is the clean checkout to copy, while these manifests keep the Cargo package, artifact, mutation,
and validation contracts reviewable in the Wild repository. The proc-macro profile sets
`"target": null` deliberately: Cargo builds proc-macro crates for the host, and on the qualified
machine that host is ARM64 macOS; passing `--target` would suppress the host linker selection
evidence.

Each workload explicitly records whether it is `stable_layout_cache_eligible`. Eligible executable
profiles must produce a verified cache hit when `--wild-incremental-cache` is supplied, and their
direct replay is held to the cache-link target. Ineligible profiles still measure their normal
incremental final link, peak RSS, CPU, output bytes, and validation evidence, but neither request
cache sidecars nor use the cache-link target as a gate. The proc-macro dylib profile is ineligible
because the cache only supports executables. The native/C++ profile remains eligible: it changes a
live fixed-width Rust data value while retaining the native static archive, so it verifies that an
unchanged static archive does not block a safe cache baseline.
The Cargo linker-stress profile is eligible for the deliberately narrow Rustc-private extension:
it accepts only terminal `.llvm.<decimal>` discriminator churn on private definitions and their
undefined references, plus a reordering of otherwise identical relocation groups. Every ordinary
symbol, section footprint, relocation payload, patch range, output nlist slot, code-signature page,
and runtime check remains bound. Other Rust codegen changes remain a normal-link cache miss.

The macOS incremental-link objective is more demanding than a normal-path comparison:
on a matched baseline-to-changed Cargo topology, a persistent-cache candidate must produce a
verified hit on every replay and have a median direct-link time at most `0.333×` Apple ld64's
unchanged changed-link control. Five interleaved replays rank candidates; an 11-replay confirmation
is required before promotion. The workload's `0.5×` setting remains the minimum regression gate;
the `0.333×` direct screen is the current promotion target. A normal-link result is diagnostic
context only; never relabel it as progress toward the cache target.

Each workload's `incremental_mutation` is an exact append or exact one-occurrence replacement.
Prefer a same-size replacement that changes a real emitted byte over a comment-only edit. For a
stable-layout linker fast path, prefer a fixed-width code immediate rather than a string literal:
changing merged-string content may legitimately change output layout even when the source edit is
the same size.

## macOS Cargo parity iteration

The active macOS optimization target is `~/d/cargo`, using
[`benchmarks/cargo.benchmark.json`](benchmarks/cargo.benchmark.json). It changes one live Cargo
source expression and builds the `linker-stress` profile: `opt-level = 3`, aborting panics,
stripping, 16 codegen units, and no LTO. This intentionally keeps Rust compilation inexpensive
enough that the final link remains visible. Its paired direct capture is the primary cache control:
it preserves the exact same `save-temps` compiler flags for baseline and changed objects, rather
than comparing two incompatible Cargo target fingerprints. The persistent-cache result is the only
promotion metric; the changed-source Cargo wall time is context only.

The Cargo checkout pins `nightly-2026-07-24` because it has no `rust-toolchain.toml`. Apple samples
omit all Wild arguments and therefore select vanilla Xcode ld64. Every Wild sample is required to
retain ARM64 header evidence, strict `codesign` evidence, the Cargo `--version` runtime smoke check,
and the direct-link RSS measurement. The promotion target is a `100%` verified cache-hit rate and
a direct-link median at or below `0.333×` Apple ld64 on the matched paired-capture cache screen;
cold builds, unrelated compile throughput, and an ordinary cache miss do not participate in that
decision.

### Full-image cache ceiling and resident-service status

The first verified Rustc-private cache hit measured `90.7 ms` against `171.5 ms` for Apple ld64
(`0.529×`) on the paired Cargo capture. Eliminating the per-hit sidecar checkpoint improved the
ordinary cache path to `82.1 ms` against `173.3 ms` (`0.473×`): it retains its immutable baseline
until all 32 bounded direct-object changes need a rebase. This preserves a normal-link recovery
path while removing an unnecessary second 29 MB write from ordinary one-object iterations.

The experimental macOS-only resident service, enabled with
`WILD_MACHO_INCREMENTAL_CACHE_SERVICE=1`, keeps one validated current image and mutable input
state in a same-user Unix-socket process. It exits after 10 seconds by default. Set
`WILD_MACHO_INCREMENTAL_CACHE_SERVICE_IDLE_SECONDS=120` for a warm Cargo screen: that bounded
interval covers incremental Rust code generation between final links without retaining the service
indefinitely. Set
`WILD_MACHO_INCREMENTAL_CACHE_SERVICE_DIR=$HOME/.cache/wild/services` when a long cache-root path
would exceed the macOS socket-path limit. A native macOS client built from
`wild/src/bin/macho-cache-client.c` submits raw linker argv without starting the Rust linker on a
hit. The resident Rust service remains authoritative: it parses, validates, patches, signs, and
publishes the output; every miss `exec`s the configured Wild binary. The listener uses event-driven
readiness, then switches accepted streams back to blocking mode so a partially written request is
never mistaken for a cache miss. A missing, stale, or failed service request falls through to the
ordinary cache/normal-link recovery path. The socket and short-lived process live below
`~/.cache/wild`; different cache roots use distinct hashed sockets and the direct screen removes
its exact completed-screen socket. On APFS, a resident hit stages a copy-on-write clone, patches
only its changed pages, and atomically publishes it. The service keeps a private clone only while
it is alive, then removes it on the bounded idle exit; this avoids a repeated full executable
write without turning the warm image into permanent cache growth.

The thin client plus resident service confirmed `54.77 ms` against `172.15 ms` for Apple ld64 on
the 11-replay paired Cargo screen (`0.318×`, `3.14×` faster). Every timed result had the normal
cache-hit marker plus strict `codesign` and Cargo runtime validation.

### Rustc parent-side inline cache

`macho-cache-inline.c` is an additional, explicitly opt-in macOS client for warmed Cargo links.
Rustc already owns the complete linker argv when it calls `posix_spawn`; the injected library
sends that argv to the same verified resident service in the Rustc parent. A cache hit publishes
the signed output there, then replaces the expensive linker child with `/usr/bin/true` while
preserving Rustc's original spawn attributes and file actions. It also handles `posix_spawnp` for
PATH-resolved clients. A miss uses the untouched linker argv with the original spawn behavior. The
Rust service remains the sole authority for parsing, validation, patching, signing, and
publication.

Build the standalone cache client and the injected library together, then make Rustc use the
client as a direct Darwin linker. `DYLD_INSERT_LIBRARIES` must reach the real Cargo and Rustc
binaries; Rustup's proxy deliberately strips it, so resolve the selected toolchain first and set
`RUSTC` to that real compiler. The library considers only link commands containing
`-incremental_cache` and the explicit inline opt-in.

```sh
cache_client="$cache_root/wild-macho-cache-client"
inline_client="$cache_root/wild-macho-cache-inline.dylib"
service_dir="$cache_root/services"
cache_dir="$cache_root/stable-layout-cache"
wild_server="$cargo_target/aarch64-apple-darwin/dist/wild"
toolchain="nightly-2026-07-24"
rustc="$(rustup which rustc --toolchain "$toolchain")"
cargo="$(rustup which cargo --toolchain "$toolchain")"

cc -O2 -Wall -Wextra -Werror wild/src/bin/macho-cache-client.c -o "$cache_client"
cc -dynamiclib -O2 -Wall -Wextra -Werror wild/src/bin/macho-cache-inline.c -o "$inline_client"

export DYLD_INSERT_LIBRARIES="$inline_client"
export WILD_MACHO_INCREMENTAL_CACHE_INLINE=1
export WILD_MACHO_INCREMENTAL_CACHE_SERVICE=1
export WILD_MACHO_INCREMENTAL_CACHE_SERVICE_DIR="$service_dir"
export WILD_MACHO_INCREMENTAL_CACHE_SERVICE_SERVER="$wild_server"
export WILD_MACHO_INCREMENTAL_CACHE_SERVICE_IDLE_SECONDS=120
export RUSTC="$rustc"
export RUSTFLAGS="-Z unstable-options -C linker=$cache_client -C linker-flavor=darwin -C link-arg=-incremental_cache -C link-arg=$cache_dir"

"$cargo" build --target aarch64-apple-darwin
```

Set `WILD_MACHO_INCREMENTAL_CACHE_INLINE_DIAGNOSTICS=1` only when diagnosing the parent boundary;
it reports inspection and either the replacement marker or the conservative cache-miss fallback.
The integration test
`macho/aarch64/stable-layout-cache-inline-parent/default` compiles the dynamic library, exercises
non-null `posix_spawn` and `posix_spawnp` file-action and attribute objects, and verifies the
cache-published binary with strict `codesign` plus a runtime exit check.

The direct `posix_spawn` screen of the matched Cargo capture measured a 13.071 ms median across 14
cache hits, against the retained 173.005 ms Apple ld64 control: `0.0756×`, or `13.236×` faster.
Its exact artifact is
`~/.cache/wild/benchmarks/cargo-inline-direct-posix-spawn-hot-2026-08-22.json`. It replays the raw
Cargo linker argv from a Rustc-equivalent direct `posix_spawn` parent and alternates a four-byte
semantically equivalent AArch64 `ret`/`br x30` change in one captured direct object. The 21.749 ms
first cache hit creates the private APFS clone and is excluded; the 14 timed transitions reuse it.
Every included sample emitted the cache-hit marker; the last output passed strict `codesign`, was
ARM64 Mach-O, and `cargo --version` returned successfully. Separately, a real `cargo rustc`
baseline followed by both `min(100, …) → min(101, …)` and reverse edits each emitted the inline
inspection, cache-hit, and replacement markers, then passed the same signing/runtime checks.
That execution uses a cache-owned target path rather than `/tmp`: Rustc preserves the `/tmp`
argument spelling while macOS canonicalizes it to `/private/tmp`, which intentionally fails the
cache's no-symlink moved-object proof. The integration test separately verifies direct and
PATH-resolved parent calls with non-null spawn attributes and file actions. The timed screen is a
warmed incremental-link boundary after Rustc has formed its linker argv, not a full Cargo build or
a service-start result. Keep strict signing and runtime checks for every promotion, and do not
claim a warm-link result from a cold build or a daemon restart.

### One authoritative qualification run

Use this only to qualify a promoted candidate, not to screen every idea. It is deliberately
serialized and interleaves Apple and Wild. Parallel wall-time measurements on the same Mac compete
for CPU, APFS cache, memory pressure, and thermals, so they cannot provide a fair comparison.

```sh
cache_root="$HOME/.cache/wild"
cargo_target="$cache_root/wild-build"

CARGO_TARGET_DIR="$cargo_target" \
  /opt/homebrew/opt/rustup/bin/cargo +nightly-2026-07-24 \
  build --locked --profile dist --target aarch64-apple-darwin -p wild-linker --bin wild \
  --no-default-features --features fork

python3 benchmarks/cargo_link_benchmark.py \
  --config benchmarks/cargo.benchmark.json \
  --workspace "$HOME/d/cargo" \
  --cargo /opt/homebrew/opt/rustup/bin/cargo \
  --wild "$cargo_target/aarch64-apple-darwin/dist/wild" \
  --scratch-root "$cache_root/workspaces" \
  --repetitions 5 \
  --link-repetitions 5 \
  --resource-link-repetitions 1 \
  --wild-timing-json \
  --output "$cache_root/benchmarks/cargo-qualified-$(date +%F).json" \
  --enforce-goals
```

The successful runner keeps only this JSON result by default. It contains selected Wild phase
records and validation evidence. `--keep-artifacts` is troubleshooting-only: it retains raw Cargo
logs and replay outputs, which can consume hundreds of megabytes. Failed runs follow the same
cleanup policy; add `--keep-artifacts` before a diagnostic run when those artifacts are needed.

### Fast candidate funnel

The qualification command runs several Cargo builds per linker because it measures Cargo wall time
and creates fresh `save-temps` inputs for direct replay. The normal Cargo profile omits the extra
cold `save-temps` capture because cold performance is context only; it retains the one cold build
needed to establish a real incremental rebuild. Treat qualification as a signoff gate, not an
experiment loop. The normal loop is:

| Stage | Purpose | Parallelism and isolation | Promotion rule |
| --- | --- | --- | --- |
| Candidate queue | Give every source idea or option setting a stable ID, a hypothesis, a focused test, and a separate cache root. Build and test the candidates before any timing. | Safe to parallelize, subject to a disk budget. Source worktrees and `CARGO_TARGET_DIR`s go under `~/.cache/wild/variants/<id>/`; they must never share a target directory. | Discard failed or contract-changing candidates before they reach the timer. |
| Capture one immutable changed link | Build Cargo once, apply the workload mutation, and retain the changed final-link argv, inputs, output contract, and checksums. | Serialized once per Cargo revision/toolchain under `~/.cache/wild/captures/<id>`. The verified capture is read-only. | The capture passes ARM64 header, strict codesign, and runtime validation before reuse. |
| One batched direct screen | Put every surviving binary/configuration in one `cargo_direct_screen.py` command. It replays the immutable input with a short interleaved series and `--time=json` for Wild. | Compilation and analysis may run in parallel; same-host timing stays serial and round-robin with one Apple control. Do not run concurrent screens on the same host. Separate machines require their own capture, Apple control, and result file. | Promote only a repeatable direct-link win with no correctness or RSS regression. A batch without a clear winner gets a diagnostic/profile pass, not another full Cargo benchmark. |
| Diagnostic attribution | Use the saved replay once to find the slow critical-path phase or thread imbalance before proposing the next structural change. This is a profiler run, never a timing result or promotion gate. | Keep any instrumented build and trace in `~/.cache/wild/variants/<id>/`, inspect the summary, then delete that exact variant root. Do not collect repeated traces to choose between sub-millisecond changes. | The next candidate names the measured phase or hot path it is meant to reduce. |
| Full qualification | Run the command above once for the selected candidate. | Serialized; this is the sole source for Cargo-incremental and final direct-link claims. | Both requested median ratios are ≤1.0 with validation and RSS evidence. |

This produces useful parallelism without corrupting measurements: expensive candidate compilation,
focused tests, and offline analysis overlap; the short timing batch is the only serialized section.
Keep a small candidate ledger beside the result JSON (candidate ID, binary hash, changed files,
hypothesis, direct-screen ratio, and disposition). It prevents rerunning Cargo merely to rediscover
a non-winning scheduling tweak. Cap concurrent builds by available disk, and delete the exact
`~/.cache/wild/variants/<id>` root as soon as that candidate is rejected.

Treat an individual result JSON as a paired experiment, not an absolute stopwatch. CPU frequency,
thermal state, and filesystem cache state can move raw medians substantially between screens. A
candidate therefore must appear in the same round-robin screen as the accepted baseline; do not
promote it by comparing medians from separate reports. Use five interleaved repetitions to rank a
batch, then run one 11-repetition baseline-versus-winner confirmation before the full Cargo gate.

`benchmarks/cargo_direct_capture.py` and `benchmarks/cargo_direct_screen.py` implement the capture
and direct-screen stages. A capture records the clean Cargo revision, toolchain, complete direct
command, every existing file argument's checksum, and the validated output contract. A screen
rehashes those inputs before it starts, so it refuses to silently reuse a stale target tree.

```sh
cache_root="$HOME/.cache/wild"
capture_root="$cache_root/captures/cargo-$(git -C "$HOME/d/cargo" rev-parse --short HEAD)"
cargo_target="$cache_root/wild-build"

python3 benchmarks/cargo_direct_capture.py \
  --config benchmarks/cargo.benchmark.json \
  --workspace "$HOME/d/cargo" \
  --cargo /opt/homebrew/opt/rustup/bin/cargo \
  --capture-root "$capture_root"

python3 benchmarks/cargo_direct_screen.py \
  --capture "$capture_root/manifest.json" \
  --candidate current="$cargo_target/aarch64-apple-darwin/dist/wild" \
  --candidate groups-96="$cargo_target/aarch64-apple-darwin/dist/wild" \
  --candidate-env groups-96=WILD_FILES_PER_GROUP=96 \
  --candidate threads-8="$cargo_target/aarch64-apple-darwin/dist/wild" \
  --candidate-arg threads-8=--threads=8 \
  --repetitions 5 \
  --output "$cache_root/benchmarks/cargo-direct-screen-$(date +%F).json"
```

The capture performs exactly two unmeasured Cargo builds: a baseline and its one-source-change
successor, both with `-C save-temps`. It retains both immutable direct commands and input records
in the same manifest, so persistent-cache work never compares artifacts generated with different
Rustflags fingerprints. The ordinary direct screen continues to use the changed command. The
capture retains its copied workspace and target tree so those direct inputs remain valid; it can
therefore be substantial. After verifying both input sets, it prunes the target tree to only the
paired direct inputs and output paths; discarded `save-temps` bitcode and logs do not accumulate.
A failed partial capture is removed by default;
`--keep-failed-capture` is the explicit diagnostic escape hatch.
The screen removes disposable output artifacts on either success or failure unless
`--keep-artifacts` is supplied, leaving its JSON result on success. After selecting a winner or
invalidating the input revision, remove that exact `"$capture_root"` directory. Do not run two
screens concurrently on the same Mac; instead, build and test variants in parallel, then put all
surviving candidates in one round-robin screen with the shared Apple control. Use separate
machines only when each has its own capture and Apple controls.

For persistent-cache work, pass `--stable-layout-cache` to the same direct screen. It requires a
v2 paired capture, rebuilds each candidate's baseline once with `-incremental_cache`, snapshots the
baseline image and sidecars, restores them before every changed replay, and rejects a sample unless
Wild reports a cache hit. This setup and restoration are deliberately outside the timed link.

```sh
python3 benchmarks/cargo_direct_screen.py \
  --capture "$capture_root/manifest.json" \
  --candidate cache-candidate="$cargo_target/aarch64-apple-darwin/dist/wild" \
  --stable-layout-cache \
  --repetitions 5 \
  --output "$cache_root/benchmarks/cargo-direct-cache-screen-$(date +%F).json"
```

For the experimental resident service, build the thin macOS client into the cache root and give the
service a short socket directory there. The screen's follow-on samples refresh metadata on one
verified changed object so every timed request represents a new bounded incremental input event;
its separate resource replay restores the ordinary disk baseline and disables the service.

```sh
cache_client="$cache_root/wild-macho-cache-client"
cc -O2 -Wall -Wextra -Werror wild/src/bin/macho-cache-client.c -o "$cache_client"

python3 benchmarks/cargo_direct_screen.py \
  --capture "$capture_root/manifest.json" \
  --candidate resident-cache="$cache_client" \
  --candidate-env resident-cache=WILD_MACHO_INCREMENTAL_CACHE_SERVICE=1 \
  --candidate-env resident-cache=WILD_MACHO_INCREMENTAL_CACHE_SERVICE_DIR="$cache_root/services" \
  --candidate-env resident-cache=WILD_MACHO_INCREMENTAL_CACHE_SERVICE_SERVER="$cargo_target/aarch64-apple-darwin/dist/wild" \
  --stable-layout-cache \
  --repetitions 5 \
  --output "$cache_root/benchmarks/cargo-resident-cache-screen-$(date +%F).json"
```

Use this cache mode only for a topology whose current cache implementation can prove safe. A
structural miss is useful evidence for the next implementation change, but it is not a timed result
and leaves no retained replay artifacts by default.

The latest phase profile identifies input opening, layout, and output writing as the largest visible
Wild direct-link phases. They are the first targets for a reusable-capture screen; do not repeatedly
pay for full Cargo capture builds to evaluate a tiny scheduling change.

### Disk and cleanup contract

All workflow data belongs below `~/.cache/wild`: variant builds, workspace copies, compiler
`TMPDIR`, captures, screen outputs, reports, and opt-in stable-layout sidecars. Never create
`~/d/wild-*` or `~/d/.wild-*` benchmark trees. The Python Cargo runner, direct screen, and failed
capture path reject output roots outside this cache. They remove disposable run artifacts on both
success and failure unless explicitly retained with `--keep-artifacts` or
`--keep-failed-capture`; `--keep-workspaces` likewise retains only its cache-owned workspace
copies. After inspecting an explicitly retained run or capture, delete that exact cache-owned
directory before the next large run.

Cache output is an optimization only: any unverified stable-layout-cache change must fall back to a
normal link, and the benchmark treats that fallback as a failed cache measurement rather than a
fast sample. The cache directory must be empty and contain no whitespace before an opt-in cache run
so stale sidecars cannot be mixed into a result.

### Preparing the "run-with" files

For benchmarking the linker, it's preferable to run just the linker, not the whole build process.

Keep manual captures below `~/.cache/wild/manual-captures` as well. The Cargo capture/screen
workflow above is the authoritative method for the current macOS Cargo target.

The way to do that is by capturing the linker invocation so that it can be rerun. Wild has a
built-in way to do that.

You can benchmark linking of either a debug or a release build of a crate, this depends on what
comparisons you wish to make, or what change in wild you want to quantify.

Follow-these steps:

* Chose the crate that you wish to use in your benchmark, clone it, `cd` into its root directory and
  make sure it builds with `cargo build` (for a rust project)
    * Examples: [`ripgrep`](https://github.com/BurntSushi/ripgrep.git)
* Clean the build using `cargo clean`
* To force the build of your chosen crate to link using wild, we have a couple of options:
    * Prefix the cargo build command with `RUSTFLAGS="-Clinker=clang -Clink-arg=--ld-path=wild"`
    * Modify (or add) the `.cargo/config.toml` file in your chosen crate (example for `ripgrep`)

```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-Clink-arg=--ld-path=wild"]
```

* Make sure that you have a version of wild in your `$PATH` so that it will be used (try `which
  wild` to check)
* Run `WILD_SAVE_BASE=$HOME/.cache/wild/manual-captures/ripgrep cargo build` in the crate's root directory (include
  `RUSTFLAGS` as above if you have chosen that method)
* You will get a few numbered subdirectories in `$HOME/.cache/wild/manual-captures/ripgrep` as part of the build process.
    * Directories will be created for builds of build scripts, proc macros and crate binaries built
    * Usually the last numbered subdirectory will be the build of crate's binary (if a single binary
      is built)
    * You can check what each file is linking using `tail -n 1 $HOME/.cache/wild/manual-captures/ripgrep/*/run-with`
    * In the case of ripgrep it is '6'
* You can then run `$HOME/.cache/wild/manual-captures/ripgrep/6/run-with wild` and that will rerun the link with wild

When you run `run-with wild`, the linker may print warnings for unsupported flags. It's a good idea
to edit the `run-with` script to change / delete these flags. This will make comparison with other
linkers fairer, since some of these unsupported flags may involve other linkers doing significant
amounts of extra work.

### Run benchmark with hyperfine

Let's benchmark the linking stage between `ld`, `mold` and `wild`, discarding the first two runs of
each to reduce the effects of cache warmup

```shell
hyperfine --warmup 2 "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with ld" "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with mold" "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with wild"
```

That should produce output similar to this (with different values):

```text
Benchmark 1: ~/.cache/wild/manual-captures/ripgrep/6/run-with ld
  Time (mean ± σ):     954.1 ms ±  13.6 ms    [User: 683.4 ms, System: 268.8 ms]
  Range (min … max):   920.6 ms … 970.7 ms    10 runs
 
Benchmark 2: ~/.cache/wild/manual-captures/ripgrep/6/run-with mold
  Time (mean ± σ):     146.1 ms ±   3.6 ms    [User: 52.0 ms, System: 2.4 ms]
  Range (min … max):   139.1 ms … 154.7 ms    19 runs
 
Benchmark 3: ~/.cache/wild/manual-captures/ripgrep/6/run-with wild
  Time (mean ± σ):      87.7 ms ±   2.8 ms    [User: 2.4 ms, System: 2.0 ms]
  Range (min … max):    81.5 ms …  92.5 ms    34 runs
 
Summary
  ~/.cache/wild/manual-captures/ripgrep/6/run-with wild ran
    1.67 ± 0.07 times faster than ~/.cache/wild/manual-captures/ripgrep/6/run-with mold
   10.88 ± 0.38 times faster than ~/.cache/wild/manual-captures/ripgrep/6/run-with ld
```

### Run benchmark with poop

An alternative tool to hyperfine, that reports some additional metrics is [
`poop`](https://github.com/andrewrk/poop).

Like hyperfine it takes a number of commands and runs each a number of times and gathers statistics
about each tune.

```shell
poop "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with ld" "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with mold" "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with wild"
```

It should produce output similar to this (with different numbers!):

```text
Benchmark 1 (5 runs): ~/.cache/wild/manual-captures/ripgrep/6/run-with ld
  measurement          mean ± σ            min … max           outliers         delta
  wall_time          1.18s  ±  335ms     926ms … 1.68s           0 ( 0%)        0%
  peak_rss            288MB ±  276KB     287MB …  288MB          1 (20%)        0%
  cpu_cycles         2.51G  ±  341M     2.28G  … 3.06G           0 ( 0%)        0%
  instructions       3.93G  ± 9.54K     3.93G  … 3.93G           0 ( 0%)        0%
  cache_references   98.7M  ± 2.59M     96.4M  …  102M           0 ( 0%)        0%
  cache_misses       41.9M  ± 2.52M     40.3M  … 46.3M           0 ( 0%)        0%
  branch_misses      9.77M  ±  223K     9.62M  … 10.2M           0 ( 0%)        0%

Benchmark 2 (31 runs): ~/.cache/wild/manual-captures/ripgrep/6/run-with mold
  measurement          mean ± σ            min … max           outliers         delta
  wall_time           165ms ± 27.2ms     149ms …  280ms          2 ( 6%)        ⚡- 86.0% ±  9.9%
  peak_rss           7.84MB ± 96.3KB    7.60MB … 8.00MB         11 (35%)        ⚡- 97.3% ±  0.0%
  cpu_cycles         2.01G  ± 38.6M     1.97G  … 2.16G           2 ( 6%)        ⚡- 19.9% ±  4.8%
  instructions       1.99G  ± 3.12M     1.98G  … 1.99G           3 (10%)        ⚡- 49.3% ±  0.1%
  cache_references   44.8M  ±  250K     44.4M  … 45.6M           1 ( 3%)        ⚡- 54.6% ±  0.9%
  cache_misses       21.6M  ±  461K     21.3M  … 23.6M           3 (10%)        ⚡- 48.4% ±  2.3%
  branch_misses      7.17M  ± 37.7K     7.07M  … 7.25M           1 ( 3%)        ⚡- 26.6% ±  0.8%

Benchmark 3 (56 runs): ~/.cache/wild/manual-captures/ripgrep/6/run-with wild
  measurement          mean ± σ            min … max           outliers         delta
  wall_time          89.1ms ± 3.14ms    83.0ms … 96.6ms          0 ( 0%)        ⚡- 92.4% ±  7.0%
  peak_rss           3.82MB ± 50.7KB    3.80MB … 3.93MB         10 (18%)        ⚡- 98.7% ±  0.0%
  cpu_cycles         1.26G  ± 15.1M     1.21G  … 1.31G           7 (13%)        ⚡- 49.6% ±  3.4%
  instructions       1.21G  ±  529K     1.21G  … 1.22G           5 ( 9%)        ⚡- 69.1% ±  0.0%
  cache_references   33.9M  ±  467K     32.9M  … 34.9M           0 ( 0%)        ⚡- 65.7% ±  0.8%
  cache_misses       14.4M  ±  187K     14.1M  … 14.9M           0 ( 0%)        ⚡- 65.6% ±  1.5%
  branch_misses      3.49M  ± 7.86K     3.47M  … 3.51M           0 ( 0%)        ⚡- 64.2% ±  0.6%
```

NOTE: Both `mold` and `wild` fork a child process and perform linking in it. Thus, the values for
`peak_rss`, `User` and `System` are for the parent process only, and hence are not representative of
real use by the linker. To avoid this problem, pass `--no-fork` to mold and wild.

NOTE: `poop` uses the first command as the reference the others are compared against, so if focusing
on wild, you might want to re-order the commands and invoke `poop` thus:

```text
poop "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with wild" "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with mold" "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with ld"
```

### Comparisons

Using this method, you can benchmark:

* between Wild and one or more other linkers
* between different options passed to Wild - You can pass arbitrary additional arguments to
  run-with. The first argument needs to be the name of the linker to use. All additional arguments
  are passed through to the linker as-is

### Caching

The use of the linux file system cache affects linker performance, as there is a lot of reasonably
large files read and written. In a normal build, the object files being linked would be written
previously by the compiler and may well be in the file cache. With this benchmarking method we skip
the previous build steps and the linker incurs the penalty of reading those files into cache the
first time they are read.

To reduce the effect this has on benchmarked time we run hyperfine with the `--warmup 2` option, and
the results of the first two runs are not used in the calculations.

### Disk write bottlenecks

When benchmarking, if the output file is being written to persistent storage (hard disk or SSD), the
writes can build up and cause the linkers to block. Worse, writes from a previous linker invocation
might contribute to this backlog. Whether this happens depends on how much RAM you have free and
also your kernel settings. For example, if you run `cat /proc/sys/vm/dirty_ratio` that will show the
percentage of reclaimable memory that is allowed to be dirty (needing writing) before further writes
will block. If that shows zero, then `cat /proc/sys/vm/dirty_bytes` will show the same, but as an
absolute number of bytes. On some systems, the absolute dirty byte limit might be set as low as
256MiB, meaning that if we're writing a large output file, we can easily hit this limit. You could
increase this limit, or switch to using `dirty_ratio` of say 20% instead, but it might be better to
just take the filesystem out of the equation and write the output to a tmpfs instead. See next
section.

### Tmpfs

As discussed in the last section, writing to a physical disk can cause inconsistent benchmark
results. It can also contribute to wearing out your SSD. For these reasons, it's recommended to
benchmark with the output file on tmpfs.

If you don't already have a suitable tmpfs to use, you can create one something like the following:

```sh
sudo mkdir /benchmark
sudo mount -t tmpfs none /benchmark
```

Then when running the benchmark, set the output file to be on this filesystem. e.g.:

```sh
OUT=/benchmark/out hyperfine --warmup 2 "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with ld" "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with mold" "$HOME/.cache/wild/manual-captures/ripgrep/6/run-with wild"
```

### Watch out for thermal throttling

If your CPUs get hot while running the benchmark, this can cause inconsistent results. You can check
for throttle events by looking for increases in
`/sys/devices/system/cpu/cpu*/thermal_throttle/package_throttle_count` and
`/sys/devices/system/cpu/cpu*/thermal_throttle/core_throttle_count` between when you start the
benchmark and when you finish. Ideally, these should be unchanged.

One thing that can help is if you have a way to turn your fans to maximum before you start the
benchmark run.

Another possibility is to give the CPUs a chance to cool down between each run, e.g. by sleeping.
With `hyperfine`, you can do this by adding an argument like `--prepare "sleep 2"`. You might need
to experiment with the duration of the sleep.

## What to benchmark

### rustc

When building rustc, most of the rustc code goes into a shared object called rustc-driver. This
shared object is about 230 MiB without debug info and 462 MiB with debug info. While not as large as
some binaries, this is still a pretty reasonable size, making it good for benchmarking. It's also an
interesting benchmark because it's a shared object rather than an executable.

Before building rustc, edit or create `bootstrap.toml` in your `rust` directory to contain:

```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-Clink-arg=--ld-path=wild"]
```

Now rustc will use wild as the linker on every build. You must have wild in your PATH. In the
following command, replace `$WILD_REPO_PATH` with the path to the directory containing the wild
repo. You'll need to have already built wild with `cargo build --release`.

To build rustc just cd into the rust repo root and run:

```sh
PATH="$WILD_REPO_PATH/target/release:$PATH" WILD_SAVE_BASE="$HOME/.cache/wild/manual-captures/rustc-link" ./x build rustc
```

For more information about building rustc
see [building instructions on the rustc-dev-guide](https://rustc-dev-guide.rust-lang.org/building/how-to-build-and-run.html).
You should now have a few subdirectories under `$HOME/.cache/wild/manual-captures/rustc-link`. You can identify which one is
`rustc_driver` by looking at the last line of the `run-with` script in each directory.

If the directory `$HOME/.cache/wild/manual-captures/rustc-link` didn't get created, then most likely wild wasn't used to link.

### Other tools

* [poop](https://github.com/andrewrk/poop) - gives a lot of measurements other than just time. Note
  that the `peak_rss` measurement won't be accurate for wild and mold unless you include the
  `--no-fork` argument to the linker.

## Profiling

### --time

To figure out where wild is spending time, the first option is to run with `--time`. It's
recommended to combine this with `--no-fork`. For example:

```
$HOME/.cache/wild/manual-captures/rustc-link/0/run-with target/release/wild --strip-debug --time --no-fork
┌───    3.84 Open input files
├───    7.45 Split archives
├───    9.59 Parse input files
│ ┌───    2.91 Parse version script
│ ├───   16.67 Read symbols
│ ├───   15.21 Populate symbol map
├─┴─   37.68 Build symbol DB
│ ┌───   29.02 Resolve symbols
│ ├───   33.59 Resolve sections
│ ├───    2.20 Assign section IDs
│ ├───   15.39 Merge strings
│ ├───    0.04 Canonicalise undefined symbols
│ ├───    4.63 Resolve alternative symbol definitions
├─┴─   84.97 Symbol resolution
│ ┌───   76.63 Find required sections
│ ├───    0.16 Merge dynamic symbol definitions
│ ├───   18.74 Finalise per-object sizes
│ ├───    0.12 Apply non-addressable indexes
│ ├───    0.06 Compute total section sizes
│ ├───    0.01 Compute segment layouts
│ ├───    0.00 Compute per-alignment offsets
│ ├───    0.14 Compute per-group start offsets
│ ├───    0.00 Compute merged string section start addresses
│ ├───   18.10 Assign symbol addresses
│ ├───    0.30 Update dynamic symbol resolutions
├─┴─  114.85 Layout
│ ┌───    0.00 Wait for output file creation
│ │ ┌───    0.63 Split output buffers by group
│ ├─┴─  157.42 Write data to file
│ ├───   15.05 Sort .eh_frame_hdr
├─┴─  172.71 Write output file
│ ┌───   14.45 Unmap output file
│ ├───    7.27 Drop layout
│ ├───    0.01 Drop symbol DB
│ ├───   23.35 Drop input data
├─┴─   45.15 Shutdown
└─  481.09 Link
```

If a benchmark has shown a significant increase in say CPU cycles or instructions, then it can be
useful to check which phase or phases that increase has occurred in. You can get per-phase cycle and
instruction counts by running with `--time=cycles,instructions`. To see the full list of counters,
search `args.rs` for "branch-misses".

For a scriptable report, use `--time=json` (or, for example,
`--time=json,cycles,instructions`). It writes one JSON Lines record to stdout as each selected
link-critical phase completes: generic input/layout/output phases plus the major Mach-O writer and
stable-layout-cache phases. The human `--time` tree remains exhaustive. Bounding JSON output is
important: emitting a record for every live atom would perturb the link being measured. Each
record has a stable `schema_version`, `event`, `output`, `name`, `wall_time_ns`, and `counters`
array. Each counter is an object with stable
`name` and `value` fields; unavailable counters are omitted. Parallel phase records can complete
in a different order between runs. The output path makes a mixed Cargo log distinguish the final
`cargo` link from build-script, dependency, and incremental relinks. This is
intentionally opt-in, like the existing human timing tree.

The ARM64 Mach-O writer has specific phases for export-trie construction, object copying, dynamic
tables, unwind tables, chained fixups, UUID hashing, and code-signature hashing. Start with this
view for a saved Cargo replay before collecting a Perfetto trace or a sampled profile.

### Perfetto

The `--time` flag only shows the course stages of the linker. To see what each thread is doing
during each stage, we can capture a perfetto trace and view the results in the perfetto UI.

Use Perfetto only after the bounded `--time=json` phase report cannot identify the next
structural target. Build an instrumented binary in its own disposable cache root, then remove
that root after inspection:

```sh
profile_root="$HOME/.cache/wild/variants/perfetto-diagnostic"
CARGO_TARGET_DIR="$profile_root/target" \
  cargo build --profile dist --features perfetto
```

Run one replay with `WILD_PERFETTO_OUT` set inside that root. e.g.:

```sh
WILD_PERFETTO_OUT="$profile_root/wild.pftrace" ./run-with "$profile_root/target/dist/wild"
```

Open the [perfetto UI](https://ui.perfetto.dev/). Click "Open trace file" and select `wild.pftrace`.
Use the keys w, a, s, d to navigate (scroll and zoom).

The trace records wall time across workers, so use it to find a bottleneck or imbalance, not to
compare candidate speed. Delete the exact `"$profile_root"` directory after extracting that
diagnosis; the ordinary direct screen remains the only timing authority.

### Samply

To look for hot functions and to check how the work distribution looks between threads, you can use
[samply](https://github.com/mstange/samply).

For this to be useful, you likely want optimisations and debug info. We have an `opt-debug` profile
set up for this purpose.

```sh
cargo build --profile opt-debug
```

```sh
$HOME/.cache/wild/manual-captures/rustc-link/0/run-with samply record target/opt-debug/wild --strip-debug
```

The result will look something [like this](https://share.firefox.dev/4eORM7r). This is using the
Firefox profiler, so you'll need to open that link in Firefox.

One thing you'll likely notice when looking at the flamegraph is that there's lots of rayon stuff
and that makes it hard to see what's going on. The issue is that rayon uses recursion and the exact
sequence of calls it goes through before it gets to our code varies. The trick to seeing through
this is to collapse that recursion. For example, find
`rayon::iter::plumbing::bridge_producer_consumer::helper`, right click and select `Collapse
recursion` (or 'r'). If there's any extra rayon stack frames that you'd like to ignore, you can
select them and press 'm' to merge them.

### Heap profiling with dhat

Build with profiling enabled:

```sh
cargo build --profile opt-debug --features dhat
```

Then run the linker on some input. e.g:

```sh
$HOME/.cache/wild/manual-captures/rustc-link/0/run-with target/opt-debug/wild --no-fork
```

This should print some stats on exit. e.g.:

```
dhat: Total:     250,699,127 bytes in 130,224 blocks
dhat: At t-gmax: 111,265,627 bytes in 14,117 blocks
dhat: At t-end:  96,320 bytes in 109 blocks
dhat: The data has been saved to dhat-heap.json, and is viewable with dhat/dh_view.html
```

You can then upload `dhat-heap.json` to
the [online dhat viewer](https://nnethercote.github.io/dh_view/dh_view.html).

For more details, see the [dhat docs](https://docs.rs/dhat/latest/dhat/).

### Generating report-style benchmarks

Benchmarks such as [benchmarks/ryzen-9955hx.md](benchmarks/ryzen-9955hx.md) are generated using the
tool in `benchmarks/runner`. You'll need a directory containing one or more "save-dirs" where the
names of the directories are the names of the benchmarks.

```sh
cargo run --bin benchmark-runner -- \
    bench --config benchmarks/ryzen-9955hx.toml --save "$HOME/.cache/wild/saves" linker1 linker2 linker3
cargo run --bin benchmark-runner -- report
```
