# Security policy

## Scope

vanity-generator creates OpenPGP private keys, so its design is deliberately conservative. This project has not been independently audited. Review the source before using generated keys for anything important.

## Design guarantees

- **Randomness.** Every Ed25519 seed is 32 fresh bytes from the operating system CSPRNG (`BCryptGenRandom` with the system preferred RNG on Windows, `getrandom` on Linux). The program aborts if the generator fails and refuses to start if two consecutive draws are identical or all zero. No pseudo random generator, user supplied seed, clock value or counter is used for key material. Keys are never derived from one another, which avoids the weak-seed and incremental-key design flaws that made earlier vanity address generators exploitable.
- **No private keys on the GPU.** The GPU receives public keys, creation times and the search pattern only. Seeds stay in CPU memory and are wiped after each batch is processed.
- **No network access.** The program does not include or call any networking API, does not link any networking library and has no update check or telemetry. The only operating system services it uses are the random generator, the console, files you name with `--output`, and the CUDA runtime.
- **Memory hygiene.** Seeds, expanded keys, nonces and serialized key packets are overwritten after use (best effort, as with any user-space program).
- **Side channels.** The fixed-base scalar multiplication selects table entries without secret-dependent addressing, and the scalar reduction is branch-free.
- **Result verification.** Every GPU hit is recomputed on the CPU before a key is written, and a known-answer self-test runs on the GPU at start-up.
- **Selection does not weaken keys.** The search only chooses among independent random keys, and the fingerprint pattern reveals nothing about a private key.

## Things to be aware of

- The exported private key block is **not passphrase protected**. Import it into GnuPG (which asks for a passphrase), then delete the file. `--output` creates files with mode `0600` on POSIX systems; on Windows the file inherits the permissions of its folder. Use `--hide-secret` to keep private keys out of the console and its scrollback.
- The creation time of a vanity key is chosen by the search and may be far in the past. That is harmless for security, but it is visible to everyone who sees the key.
- The program cannot protect against malware or a compromised operating system on the machine that runs it. Generate important keys on a trusted, offline machine.

## Reporting a vulnerability

Please report vulnerabilities privately with the "Report a vulnerability" button on the Security tab of this repository instead of opening a public issue.
