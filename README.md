# vanity-generator

GPU-accelerated vanity fingerprint generator for OpenPGP (GnuPG) keys.

It looks for an Ed25519 key whose 40-digit fingerprint starts and/or ends with the digits you choose, and reports the private key together with the creation time that produces the match. Command line only. Written for NVIDIA GPUs, including the RTX 50 series (CUDA, `sm_120`).

## How it works

An OpenPGP v4 fingerprint is the SHA-1 of the public key packet, and that packet contains the key creation time. For an Ed25519 key the hashed data is exactly 54 bytes, which is a single SHA-1 block, and only the 4-byte creation time changes between candidates.

1. The CPU generates fresh random Ed25519 keys.
2. For every public key the GPU hashes every creation time between `--from` and `--to` and compares the fingerprint with your pattern.
3. Every hit is verified again on the CPU and written out as an armored private key that GnuPG can import.

The creation time is embedded in the exported key and is part of the fingerprint. If it is changed later, the fingerprint changes too.

## Requirements

- Windows 10 or 11, x64
- Visual Studio 2026 with the "Desktop development with C++" workload
- NVIDIA CUDA Toolkit 13.x with the Visual Studio Integration component (RTX 50 series needs CUDA 12.8 or newer)
- A current NVIDIA driver

## Build

1. Install Visual Studio first, then the CUDA Toolkit, so the Visual Studio Integration is registered.
2. Open `vanity-generator.slnx`, select `Release | x64` and build.

The project reads the toolkit version from the `CUDA_PATH` environment variable. If MSBuild cannot find `CUDA <version>.props`, pass the version explicitly:

```
msbuild vanity-generator.vcxproj /p:Configuration=Release /p:Platform=x64 /p:CudaVersion=13.4
```

GPU code is generated for `sm_86`, `sm_89` and `sm_120` (RTX 30, RTX 40, RTX 50). Edit `CodeGeneration` in the project file to add other architectures.

## Usage

```
vanity-generator --pattern <pattern> [options]
```

| Pattern | Meaning |
| --- | --- |
| `DEADBEEF*` | fingerprint starts with `DEADBEEF` |
| `*CAFE1234` | fingerprint ends with `CAFE1234` (the key ID ends with it too) |
| `8888*6666` | fixed start and fixed end |

A single run of `*` is stretched to fill the 40 digits. A pattern with several `*` groups must be exactly 40 characters long, and each `*` then stands for one digit.

| Option | Description |
| --- | --- |
| `--pattern <text>` | fingerprint pattern, may also be given as the first argument |
| `--prefix <hex>`, `--suffix <hex>` | alternative to `--pattern` |
| `--uid <text>` | user ID, default `Vanity Key <vanity@localhost>` |
| `--from <time>` | earliest creation time, default `2015-01-01` |
| `--to <time>` | latest creation time, default now |
| `--count <n>` | number of matches to find, default 1 |
| `--device <n>` | CUDA device index, default 0 |
| `--threads <n>` | CPU threads for key generation, default all |
| `--output <file>` | append armored private keys to this file |
| `--hide-secret` | do not print private keys to the console, needs `--output` |

Times are Unix seconds, `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS`, all in UTC. Press `Ctrl+C` to stop.

Examples:

```
vanity-generator --prefix 8888 --suffix 6666 --uid "Alice <alice@example.org>" --output alice.asc
vanity-generator "*CAFEBABE" --from 2020-01-01 --to 2024-12-31 --count 3
```

## Output

```
=== match 1 ===
fingerprint : <40 hex digits>
key id      : <last 16 hex digits>
created     : 2020-01-01 05:00:28 UTC (unix 1577854828)
private key : <64 hex digits, the Ed25519 seed>

-----BEGIN PGP PRIVATE KEY BLOCK-----
...
```

Never commit generated keys to Git. If you write output files inside a repository, add `*.asc` and `*.gpg` to its `.gitignore`.

Import the key into GnuPG and then delete the file:

```
gpg --import alice.asc
gpg --list-secret-keys --keyid-format long
```

GnuPG asks for a passphrase to protect the imported key. The key has certify and sign capabilities. To add an encryption subkey later, use `gpg --edit-key <fingerprint>` and `addkey`; the primary key and its fingerprint stay the same.

## Difficulty

Every additional fixed digit multiplies the expected work by 16, so the expected number of fingerprints per match is `16^n` for `n` fixed digits. The program prints the measured rate and the expected time per match while it runs. The search is not limited by the creation time window, because new random keys are generated continuously. Keep the window at least a few weeks wide: with a very short window the CPU cannot generate keys fast enough to keep the GPU busy.

## Security

See [SECURITY.md](SECURITY.md) for the full model. In short:

- Every key starts from 32 bytes taken directly from the operating system CSPRNG (`BCryptGenRandom` on Windows). There is no pseudo random generator, no small seed and no incrementing of keys, so each candidate is independent.
- Private keys never leave the CPU. The GPU only receives public keys and timestamps.
- The program makes no network requests and links no networking library.
- Secret material is wiped from memory after use and secret-dependent table lookups are constant time.
- Every GPU hit is verified on the CPU, and the GPU kernel is self-tested at start-up.

## Troubleshooting

- `CUDA <version>.props was not found`: install the Visual Studio Integration component of the CUDA Toolkit, or pass `/p:CudaVersion=<installed version>`.
- `nvcc fatal : Host compiler targets unsupported OS` or other host compiler errors: install the "MSVC v143 build tools" component and set `PlatformToolset` to `v143`.
- `no kernel image is available for execution on the device`: add your GPU architecture to `CodeGeneration`.

## License

Apache License 2.0, see [LICENSE.txt](LICENSE.txt).
