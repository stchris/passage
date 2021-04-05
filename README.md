> :warning: **No longer maintained**: This project was an excuse for me to do write a proper CLI tool in Rust and I no longer have the time to maintain it, especially looking at the ever growing list of security advisories, updates and releases needed. Should anyone maintain a fork to this repo please let me know if you want me to directly mention it here.

# passage

password manager with [age encryption](https://age-encryption.org/)

[![Build status](https://github.com/stchris/passage/workflows/Tests%20&%20Clippy/badge.svg)](https://github.com/stchris/passage/actions)
[![Crates.io](https://img.shields.io/crates/v/passage.svg)](https://crates.io/crates/passage)

## Installation

### Binaries and packages (preferred)

The [release page](https://github.com/stchris/passage/releases) includes binaries for Linux, mac OS ~and Windows~ (last Release for Windows is `0.5.1`) as well as `deb` files for Debian / Ubuntu.

### Build from source (for development)
With a rust toolchain present, you could do this (which makes sense if you want to contribute):

```bash
$ git clone https://github.com/stchris/passage.git

# Dependencies for Debian / Ubuntu
$ apt install libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libdbus-1-dev

$ cargo install --path .
```

## Walkthrough

`passage` creates an age-encrypted storage file, whose current default location depends on the OS family, for a given username `user`:

    Linux: `/home/user/.local/share/passage/entries.toml.age`
    mac OS: `/Users/user/Library/Application Support/entries.toml.age`
    Windows: `C:\Users\user\AppData\Roaming\passage\data\entries.toml.age`

You can create this file by running `passage init` once. Check the path to the storage folder at any time with `passage info`:

```
$ passage info
Storage folder: /home/chris/.local/share/passage/entries.toml.age
```

Now let's create a new entry with `$ passage new`:

```
Passphrase:
New Entry: email
Password for email:
```

So here we are prompted for three things:

* `Passphrase` is the secret we want to encrypt the password with
* `New Entry` is the name of the entry we want to create
* `Password for <entry>` is the password we want to store

Now `passage list` should show one entry (`email`) and we can decrypt this with either:

```
$ passage show email # the password gets copied to the clipboard
```

or

```
$ passage show --on-screen email # the password is printed to the console
```

## Hooks

`passage` is able to call into [git-style hooks](https://git-scm.com/book/uz/v2/Customizing-Git-Git-Hooks) before or after certain events which affect the password database. A typical use case for hooks is if your password file is stored in version control and you want to automatically push / pull the changes when interacting with `passage`.

To use hooks you need the respective folder, its path can be seen by running `passage info`. By convention you put executable scripts inside there named after the hook you want to react on. These scripts are called and passed the event which triggered the hook as the first argument.

Existing hooks:
* `pre_load` (called before the password database gets loaded)
* `post_save` (called after an update to the password database)

These commands trigger hooks:
* `passage new` (`pre_load`, `post_save` with event name `new_entry`)
* `passage list` (`pre_load` with event name `list_entries`)
* `passage show` (`pre_load` with event name `show_entry`)
* `passage edit` (`post_save` with event name `edit_entry`)
* `passage remove` (`post_save` with event name `remove_entry`)

Example hook scripts can be found [here](https://github.com/stchris/passage/tree/main/example_hooks).

## Keyring integration

If possible, `passage` will try to store the passphrase of your database into the OS keyring. You can run `passage keyring check` to see if this works. If you no longer want the password to be stored in the keyring run `passage keyring forget`.

To skip the keyring integration, `passage` takes a global flag `--no-keyring`.

## Usage

```bash
$ passage
Password manager with age encryption

USAGE:
    passage [FLAGS] <SUBCOMMAND>

FLAGS:
    -h, --help          Prints help information
    -n, --no-keyring    Disable the keyring integration
    -V, --version       Prints version information

SUBCOMMANDS:
    edit       Edit an entry
    help       Prints this message or the help of the given subcommand(s)
    info       Display status information
    init       Initialize the password store
    keyring    Keyring related commands
    list       List all known entries
    new        Add a new entry
    remove     Remove an entry
    show       Decrypt and show an entry
```
