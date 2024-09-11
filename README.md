# PETAce-Solo

<!-- start-petace-solo-overview -->

PETAce-Solo is a C++ library that implements or wraps primitive cryptography schemes.
It is one of the many components in [the framework PETAce](https://github.com/tiktok-privacy-innovation/PETAce).

PETAce-Solo implements or wraps the following primitives that involves only one party, as implied by the same "Solo".
- Hash function: SHA-256, SHA3-256, and BLAKE2b.
- Psuedo-random number generators based on: SHAKE_128, BLAKE2Xb, and AES_ECB_CTR.
- Sampling of bytes, 32-bit unsigned integers, and 64-bit unsigned integers from the uniform distribution.
- Prime field elliptic curve group arithmetics including hash-to-curve.
- Hashing tables: Cuckoo hashing and simple hashing.
- Partially homomorphic encryption: the Paillier cryptosystem.

<!-- end-petace-solo-overview -->

## Requirements

<!-- start-petace-solo-getting-started -->

| System | Toolchain                                             |
|--------|-------------------------------------------------------|
| Linux  | Clang++ (>= 5.0) or GNU G++ (>= 5.5), CMake (>= 3.15) |

| Required dependency                           | Tested version | Use                      |
|-----------------------------------------------|----------------|--------------------------|
| [OpenSSL](https://github.com/openssl/openssl) | 1.1.1          | Cryptographic primitives |
| [GMP](https://gmplib.org)                     | 6.3.0          | Bignumer operations for GMP-based Paillier|

| Optional dependency                                    | Tested version | Use                    |
|--------------------------------------------------------|----------------|------------------------|
| [GoogleTest](https://github.com/google/googletest)     | 1.12.1         | For running tests      |
| [GoogleBenchmark](https://github.com/google/benchmark) | 1.6.1          | For running benchmarks |
| [Intel Paillier Cryptosystem Library](https://github.com/intel/pailliercryptolib) | 495beaad1f6e70741f2b5cf1279cb919fd66d894 | For partially homomorphic encryption |

## Building PETAce-Solo

We assume that all commands presented below are executed in the root directory of PETAce-Solo.

To build PETAce-Solo library (optionally with test, benchmark, and example):

```bash
cmake -S . -B build -DSOLO_BUILD_TEST=ON -DSOLO_BUILD_BENCH=ON -DSOLO_BUILD_EXAMPLE=ON
cmake --build build
```

Output binaries can be found in `build/lib/` and `build/bin/` directories.

| Compile Options          | Values        | Default | Description                                         |
|--------------------------|---------------|---------|-----------------------------------------------------|
| `CMAKE_BUILD_TYPE`       | Release/Debug | Release | Debug mode decreases run-time performance.          |
| `SOLO_BUILD_SHARED_LIBS` | ON/OFF        | OFF     | Build a shared library if set to ON.                |
| `SOLO_BUILD_BENCH`       | ON/OFF        | ON      | Build C++ benchmark if set to ON.                   |
| `SOLO_BUILD_EXAMPLE`     | ON/OFF        | ON      | Build C++ example if set to ON.                     |
| `SOLO_BUILD_TEST`        | ON/OFF        | ON      | Build C++ test if set to ON.                        |
| `SOLO_BUILD_DEPS`        | ON/OFF        | ON      | Download and build unmet dependencies if set to ON. |
| `SOLO_USE_IPCL`          | ON/OFF        | OFF     | BUILD IPCL-based PHE if set to ON, GMP-based PHE if set to off|

### Adding Partially Homomorphic Encryption

By default, the Paillier cryptosystem is a generic implementation that uses the GMP library.
For power users who seek extreme performance on supported processors, we provide the option to switch to the IPCL-based implementation.
To use the IPCL-based Paillier, follow instructions of [Intel Paillier Cryptosystem Library](https://github.com/intel/pailliercryptolib) and install it to `${IPCL_INSTALL_DIR}`.
We recommend the commit `495beaad1f6e70741f2b5cf1279cb919fd66d894` instead of v2.0.0.
Build PETAce-Solo library with extra configuration:

```bash
cmake -S . -B build -DSOLO_USE_IPCL=ON -DIPCL_DIR=${IPCL_INSTALL_DIR}/lib/cmake/ipcl-2.0.0
```
<!-- end-petace-solo-getting-started -->

## Contribution

Please check [Contributing](CONTRIBUTING.md) for more details.

## Code of Conduct

Please check [Code of Conduct](CODE_OF_CONDUCT.md) for more details.

## License

This project is licensed under the [Apache-2.0 License](LICENSE).

## Citing PETAce

To cite PETAce in academic papers, please use the following BibTeX entries.

### Version 0.3.0

```tex
    @misc{petace,
        title = {PETAce (release 0.3.0)},
        howpublished = {\url{https://github.com/tiktok-privacy-innovation/PETAce}},
        month = Jun,
        year = 2024,
        note = {TikTok Pte. Ltd.},
        key = {PETAce}
    }
```
