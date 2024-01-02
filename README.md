<img src="resources/images/logo.png" align="right" />

# Project Stellar CSO Compressor
<p >
 <a href=""><img src="https://img.shields.io/discord/643467096906399804.svg" alt="Chat"></a>
 <a href="https://github.com/MakeMHz/stellar-cso/issues"><img src="https://img.shields.io/github/issues/MakeMHz/stellar-cso.svg" alt="GitHub Issues"></a>
 <a href=""><img src="https://img.shields.io/badge/contributions-welcome-orange.svg" alt="Contributions welcome"></a>
 <a href="https://opensource.org/license/bsd-3-clause/"><img src="https://img.shields.io/github/license/MakeMHz/stellar-cso.svg?color=green" alt="License"></a>
</p>

> stellar (adj) - exceptionally good; outstanding.

The world's most powerful add-on for the Original Xbox. StellarOS is the first completely legal re-implementation of the retail Xbox BIOS.

## Usage
```bash
python3 ciso.py <ISO/XISO Path>
```

## About

Compression script is based on, and forked, from [https://github.com/phyber/ciso](https://github.com/phyber/ciso) under the BSD-3-Clause license.

Based on ciso from [https://github.com/jamie/ciso](https://github.com/jamie/ciso).

## [nerdspice](https://github.com/nerdspice/stellar-cso) fork
adds several features:
- Multi-processor support for faster compression
- Improved progress bar
- Chunked processing for more efficent processing on slower drives or over SMB
- Generates an attacher .xbe with the following pieces of data patched in from default.xbe on the iso:
  - Title
  - Title ID
  - Version
  - Title Image
- Organizes output files into game folders
- CCI support via environment variable `CISO_COMPRESS_MODE=CCI`
- ISO support via environment variable `CISO_COMPRESS_MODE=ISO`
- Allows you to set an output directory via environment variable `CISO_OUPUT_DIR=<dir>`
- Supports batch processing of multiple input files
- Converts redumps into xiso first before compressing (Windows only, atm) except for a few games that might break otherwise (TOCA 3)
- [Release binaries](https://github.com/nerdspice/stellar-cso/releases): Win-x64, Linux-x86_64, MacOS-x64
