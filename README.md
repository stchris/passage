# passage

password manager with [age encryption](https://age-encryption.org/)

[![Build status](https://github.com/stchris/passage/workflows/Tests%20&%20Clippy/badge.svg)](https://github.com/stchris/passage/actions)
[![Crates.io](https://img.shields.io/crates/v/passage.svg)](https://crates.io/crates/passage)

## Use with care

This project is in development, not ready for serious use. A lot of things might change, especially regarding the storage format which right now has one big downside: it leaks entry names.

## Installation

Right now this assumes a rust toolchain is present. As soon as the codebase is more stable I will look into providing binaries.

For now:

```bash
$ git clone https://github.com/stchris/passage.git

# Dependencies for Debian / Ubuntu
$ apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev

$ cargo install --path .
```

## Walkthrough

`passage` assumes a storage folder, whose current default is `~/.local/share/passage/entries/`. You can create this folder by running `passage init` once.


> Note: this might not work on Windows and will be adressed by [Issue #3](https://github.com/stchris/passage/issues/3).

Now let's create a new entry with `$ passage new`:

```
Entry> email
Password for email:
Enter passphrase:
```

So here we are prompted for three things:

* `entry` is the name of the entry we want to create
* `Password for <entry>` is the password we want to store
* `passphrase` is the secret we want to encrypt the password with

Now `passage list` should show one entry (`email`) and we can decrypt this with either:

```
$ passage show email # the password gets copied to the clipboard
```

or

```
$ passage show --on-screen email # the password is printed to the console
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
