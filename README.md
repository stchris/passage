# passage

password manager with [age encryption](https://age-encryption.org/)

[![Build status](https://github.com/stchris/passage/workflows/Tests%20&%20Clippy/badge.svg)](https://github.com/stchris/passage/actions)

## Use with care

This project is in development, *not ready for production use*. A lot of things might change, especially regarding the storage format which right now has one big downside: it leaks entry names.

## Installation

Right now this assumes a rust toolchain is present. As soon as the codebase is more stable I will look into providing binaries.

For now:

```bash
$ git clone https://github.com/stchris/passage.git

# Dependencies for Debian / Ubuntu
$ apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev

$ cargo install --path .
```

## Usage

```bash
$ passage
passage 0.1.0
Password manager with age encryption

USAGE:
    passage <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help    Prints this message or the help of the given subcommand(s)
    init    Initialize the password store
    list    List all known entries
    new     Add a new entry
    show    Decrypt and show an entry
```
