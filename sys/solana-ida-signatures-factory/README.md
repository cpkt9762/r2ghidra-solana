# Solana IDA Signatures Factory

This repository contains all scripts needed to generate IDA Free/Pro FLIRT signatures for Solana libraries. Use the plugin [solana-ebpf-ida-processor](https://github.com/PassKeyRa/solana-ebpf-ida-processor) to load Solana program binaries and then apply the generated signatures to detect library functions.

## Usage

### Install requirements

```bash
pip install -r requirements.txt
```

### Fetch versions list for a crate

For the `anchor-lang` crate:

```bash
python3 versions/fetch-crate-versions.py anchor-lang > versions/anchor-lang.txt
```

### Refresh full Solana + Anchor version index (official sources)

Generate a complete index from:
- GitHub releases: `anza-xyz/agave` + `solana-labs/solana`
- crates.io metadata for Solana/Anchor crates

```bash
bash versions/refresh-solana-anchor-index.sh
```

Outputs include:
- `versions/solana-release-tags.txt`
- `versions/solana-rust-crates.txt`
- `versions/anchor-crates.txt`
- `versions/missing-crates.txt` (not found on crates.io)
- `versions/<crate>.txt` for each discovered crate

### Build all crate versions using a specific solana version and extract rlibs

For the `anchor-lang` crate and solana version `1.18.26`:

```bash
python3 get-rlibs-from-crate.py \
  --solana-version 1.18.26 \
  --compiler-solana-version 1.18.16 \
  --fallback-compiler-solana-version 1.18.16 \
  --platform-tools-version v1.48 \
  --crate anchor-lang \
  --versions-file versions/anchor-lang.txt
```

This command automatically downloads the specified solana version into the `solana/` directory, fetches and builds all versions of the `anchor-lang` crate listed in the `versions/anchor-lang.txt` file. After that, for each version the resulted .rlib file is extracted and saved in the `rlibs/<crate-name>/` directory.

**If the `solana-program` crate is specified, the equal solana version will be used for each crate version**

![](img/example1.png)

### Rust compatibility strategy (vendored in r2ghidra)

This copy adds compatibility fallback so old Solana toolchains can still build crates:

1. `Cargo.lock v4` fallback: drop lock file and rebuild.
2. `edition2024` fallback: patch `blake3` lock entry `1.8.3 -> 1.8.2`.
3. `build_hasher_simple_hash_one` fallback: append `ahash = "=0.8.6"` patch.
4. Compiler fallback: `get-rlibs-from-crate.py` retries with
   `--fallback-compiler-solana-version` unless `--disable-compiler-fallback` is set.

Required version parameters (no defaults):
- `--solana-version`
- `--compiler-solana-version`
- `--fallback-compiler-solana-version`
- `--platform-tools-version`

Examples:

```bash
# Build one version using default compiler policy
python3 get-rlibs-from-crate.py \
  --solana-version 1.18.16 \
  --compiler-solana-version 1.18.16 \
  --fallback-compiler-solana-version 1.18.16 \
  --platform-tools-version v1.48 \
  --crate solana-program \
  --version 1.17.34

# Explicit compiler/fallback + tools version
python3 get-rlibs-from-crate.py \
  --solana-version 1.18.16 \
  --crate solana-program \
  --version 1.17.34 \
  --compiler-solana-version 1.18.16 \
  --fallback-compiler-solana-version 1.18.16 \
  --platform-tools-version v1.48

# Use newer platform-tools rustc with old solana wrapper
python3 get-rlibs-from-crate.py \
  --solana-version 1.18.16 \
  --crate anchor-lang \
  --version 0.29.0 \
  --compiler-solana-version 1.18.16 \
  --fallback-compiler-solana-version 1.18.16 \
  --platform-tools-version v1.48
```

### Collect compiled rlibs (including Rust core/std)

After building crates, export everything to a versioned directory tree:

```bash
bash collect-compiled-rlibs.sh /tmp/r2ghidra-solana-rlibs-by-version
```

This includes:
- toolchain core libs: `core/alloc/compiler_builtins/std` from `~/.cache/solana/*` (`sbf*`/`sbpfv3*` targets)
- compiled `solana-program` release + release/deps rlibs from `crates/*/target/{sbf-solana-solana,sbpfv3-solana-solana}/release`
- exported top-level rlibs from `rlibs/`

And writes:
- `/tmp/r2ghidra-solana-rlibs-by-version/RLIB_PATHS.txt`

### Generate .pat files via FLAIR preprocessor

```
usage: flair-preprocessor.py [-h] [-if INPUT_FOLDER] [-of OUTPUT_FOLDER] [-i INPUT_FILE] [-o OUTPUT_FILE]

Solana eBPF libraries PAT files generator

options:
  -h, --help            show this help message and exit
  -if INPUT_FOLDER, --input-folder INPUT_FOLDER
                        Folder with .rlib or .o libraries
  -of OUTPUT_FOLDER, --output-folder OUTPUT_FOLDER
                        Resulted PAT files folder (separate file for each library)
  -i INPUT_FILE, --input-file INPUT_FILE
                        Single library file
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Single resulted PAT file
```

Example:

```bash
python3 flair-preprocessor.py -if rlibs/anchor-lang/ -of sigs/anchor-lang/
```

If `-of` is specified, for every library in the `-if` folder a separate .pat file will be generated in the `-of` folder. However, if the `-o` option is used, only one .pat file will be generated with joined functions from all libraries versions. Note that in this case there is no deduplication of function signatures. Proceed to the next step if you want to deduplicate the signatures.

### Join .pat files and deduplicate signatures

```
usage: join-pat-files.py [-h] -if INPUT_FOLDER -l LIB_NAME -o OUTPUT_FILE [-dd]

options:
  -h, --help            show this help message and exit
  -if INPUT_FOLDER, --input-folder INPUT_FOLDER
                        Input folder with PAT files (<lib_name>-<version>.pat)
  -l LIB_NAME, --lib-name LIB_NAME
                        Library name (joins all versions of *.pat for that library)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Output file
  -dd, --drop-duplicates
                        Drop duplicates
```

Example:

```bash
python3 join-pat-files.py -if sigs/anchor-lang/ -l anchor_lang -o sigs/anchor-lang.pat -dd
```

The folder in the `-if` option should contain .pat files with the following naming convention: `<lib_name>-<version>.pat`. The `-l` option is the library name without the version. The `-o` option is the output file name. The optional `-dd` drops duplicates from the final .pat file.

### Generate signatures from .pat files

Use the sigmake tool the FLAIR toolkit (can be downloaded from the official Hex-Rays download center) to generate signatures from .pat files.

Example:

```bash
sigmake -nAnchorLang sigs/anchor-lang.pat sigs/anchor-lang.sig
```

### Apply signatures to a loaded binary

In IDA, navigate to `File` -> `Load file` -> `FLIRT signature file`. Click the button `Load SIG file` and select the generated .sig file.

## TODO

- Add support for solana versions >= 2.0.0
