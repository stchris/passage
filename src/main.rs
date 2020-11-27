#![forbid(unsafe_code)]
#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::panic)]
#![allow(clippy::multiple_crate_versions)]

use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;
use std::process::Command;
use std::{
    collections::HashMap,
    io::{BufReader, Read, Write},
};

use anyhow::{anyhow, Error, Result};
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use directories_next::ProjectDirs;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

const KEYRING_APP_NAME: &str = "passage";

#[derive(Debug, Deserialize, Serialize)]
struct Storage {
    #[serde(flatten)]
    entries: HashMap<String, Entry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Entry {
    password: String,
}

/// Represents callable scripts which can be triggered at certain times
enum Hook {
    PreLoad,
    PostSave,
}

impl Hook {
    fn name(&self) -> String {
        match *self {
            Self::PreLoad => "pre_load".to_string(),
            Self::PostSave => "post_save".to_string(),
        }
    }
}
/// Represents events which can trigger hooks
#[derive(Debug)]
enum HookEvent {
    NewEntry,
    ListEntries,
    ShowEntry,
}

impl HookEvent {
    fn name(&self) -> String {
        match *self {
            Self::NewEntry => "new_entry".to_string(),
            Self::ListEntries => "list_entries".to_string(),
            Self::ShowEntry => "show_entry".to_string(),
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "passage", about = "Password manager with age encryption")]
enum Opt {
    /// Initialize the password store
    Init,
    /// Add a new entry
    New,
    /// List all known entries
    List,
    /// Decrypt and show an entry
    Show {
        entry: String,

        #[structopt(long, short)]
        /// Print the password instead of copying it to the clipboard
        on_screen: bool,
    },
    /// Display status information
    Info,
    /// Keyring related commands
    Keyring(KeyringOpt),
}
#[derive(Debug, StructOpt)]
enum KeyringOpt {
    /// Checks if the keyring integration works
    Check,
    /// Deletes the password from the keyring
    Forget,
}

/// Returns the path to the storage folder containing the `entries_file`
fn storage_dir() -> Result<String> {
    match ProjectDirs::from("", "", "passage") {
        Some(pd) => {
            let dir = pd.data_dir().display().to_string();
            Ok(dir)
        }
        None => Err(anyhow!("couldn't determine project storage folder")),
    }
}

/// Returns the path to the entries.toml.age file
fn entries_file() -> Result<String> {
    Ok(Path::new(&storage_dir()?)
        .join("entries.toml.age")
        .display()
        .to_string())
}

/// Returns the path toth the hooks directory
fn hooks_dir() -> Result<String> {
    Ok(Path::new(&storage_dir()?)
        .join("hooks")
        .display()
        .to_string())
}

fn encrypt(plaintext: &[u8], passphrase: Secret<String>) -> Result<Vec<u8>, Error> {
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);

    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted).map_err(Error::msg)?;
    writer.write_all(plaintext)?;
    writer.finish()?;

    Ok(encrypted)
}

fn decrypt(encrypted: &[u8], passphrase: &Secret<String>) -> Result<Vec<u8>, Error> {
    let decryptor = match age::Decryptor::new(&encrypted[..])? {
        age::Decryptor::Passphrase(d) => d,
        age::Decryptor::Recipients(..) => unreachable!(),
    };

    let mut decrypted = vec![];
    let mut reader = decryptor.decrypt(passphrase, None)?;
    loop {
        let bytes = reader.read_to_end(&mut decrypted)?;
        if bytes == 0 {
            break;
        }
    }

    Ok(decrypted)
}

fn load_entries(passphrase: &Secret<String>) -> Result<Storage> {
    let mut encrypted: Vec<u8> = vec![];
    let file = match fs::metadata(entries_file()?) {
        Ok(_) => File::open(entries_file()?)?,
        Err(_) => File::create(entries_file()?)?,
    };
    let mut buf = BufReader::new(file);
    buf.read_to_end(&mut encrypted)?;
    if let 0 = encrypted.len() {
        Ok(Storage {
            entries: HashMap::new(),
        })
    } else {
        let decrypted = decrypt(&encrypted, passphrase)?;
        let decrypted = String::from_utf8(decrypted)?;
        let decrypted: Storage = toml::from_str(&decrypted)?;
        Ok(decrypted)
    }
}

fn save_entries(passphrase: Secret<String>, storage: &Storage) -> Result<()> {
    let bytes: Vec<u8> = toml::to_vec(&storage)?;
    let encrypted = encrypt(&bytes, passphrase)?;
    let mut file = File::create(entries_file()?)?;
    file.write_all(&encrypted)?;
    Ok(())
}

fn new_entry() -> Result<(), Error> {
    run_hook(&Hook::PreLoad, &HookEvent::NewEntry)?;
    let passphrase = get_passphrase("Passphrase: ")?;
    let mut storage = load_entries(&passphrase)?;

    print!("New entry: ");
    io::stdout().flush()?;
    let mut entry = String::new();
    io::stdin().read_line(&mut entry)?;
    let entry = entry.trim();

    if storage.entries.contains_key(entry) {
        print!("'{}' already exists. Overwrite (y/N)? ", entry);
        io::stdout().flush()?;
        let mut overwrite = String::new();
        io::stdin().read_line(&mut overwrite)?;
        let overwrite = overwrite.trim();
        if overwrite.to_uppercase() != "Y" {
            return Ok(());
        }
    }

    let password = get_passphrase(&format!("Password for {}", entry))?;
    storage.entries.entry(entry.to_owned()).or_insert(Entry {
        password: password.expose_secret().to_string(),
    });

    save_entries(passphrase, &storage)?;
    run_hook(&Hook::PostSave, &HookEvent::NewEntry)?;

    Ok(())
}

fn list() -> Result<(), Error> {
    run_hook(&Hook::PreLoad, &HookEvent::ListEntries)?;

    let passphrase = get_passphrase("Enter passphrase: ")?;
    let storage = load_entries(&passphrase)?;
    for name in storage.entries.keys() {
        println!("{}", name);
    }
    Ok(())
}

fn init() -> Result<(), Error> {
    fs::create_dir_all(storage_dir()?)?;
    let path = entries_file()?;
    if fs::metadata(path).is_err() {
        File::create(entries_file()?)?;
        let passphrase = get_passphrase("Passphrase: ")?;
        let entries: Storage = toml::from_str("")?;
        save_entries(passphrase, &entries)?
    }
    Ok(())
}

/// Gets the passphrase from either the keyring or stdin (and stores it in the keyring)
fn get_passphrase(prompt: &str) -> Result<Secret<String>> {
    let username = &whoami::username();
    let keyring = keyring::Keyring::new(KEYRING_APP_NAME, username);

    let passphrase = if let Ok(pw) = keyring.get_password() {
        Secret::new(pw)
    } else {
        let passphrase = rpassword::prompt_password_stdout(prompt)?;
        if keyring.set_password(&passphrase).is_err() {
            anyhow!("Failed to store password in keyring");
        }

        Secret::new(passphrase)
    };

    Ok(passphrase)
}

#[cfg(target_os = "linux")]
use fork::{fork, Fork};

#[cfg(target_os = "linux")]
fn copy_to_clipbpard(decrypted: String) -> Result<(), Error> {
    match fork() {
        Ok(Fork::Child) => {
            let mut ctx: ClipboardContext = ClipboardProvider::new()
                .map_err(|e| anyhow!("failed to initialize clipboard provider: {}", e))?;
            ctx.set_contents(decrypted)
                .map_err(|e| anyhow!("failed to copy to clipboard: {}", e))?;

            std::thread::sleep(std::time::Duration::from_secs(10));

            ctx.set_contents("".to_owned())
                .map_err(|e| anyhow!("failed to copy to clipboard: {}", e))?;
        }
        Err(_) => return Err(Error::msg("Failed to fork()")),
        Ok(_) => {}
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn copy_to_clipbpard(decrypted: String) -> Result<(), Error> {
    let mut ctx: ClipboardContext = ClipboardProvider::new()
        .map_err(|e| anyhow!("failed to initialize clipboard provider: {}", e))?;
    ctx.set_contents(decrypted)
        .map_err(|e| anyhow!("failed to copy to clipboard: {}", e))?;
    Ok(())
}

fn show(entry: &str, on_screen: bool) -> Result<()> {
    run_hook(&Hook::PreLoad, &HookEvent::ShowEntry)?;
    let passphrase = get_passphrase("Enter passphrase: ")?;
    let storage = load_entries(&passphrase)?;
    if storage.entries.contains_key(entry) {
        let password = &storage.entries.get(entry).unwrap().password;
        if on_screen {
            println!("{}", password);
        } else {
            copy_to_clipbpard(password.to_string())?;
        }
    } else {
        return Err(anyhow!("{} not found", entry));
    }

    Ok(())
}

fn info() -> Result<()> {
    let storage_path = entries_file()?;
    if fs::metadata(storage_path.clone()).is_ok() {
        println!("Storage file: {}", storage_path);
    } else {
        println!("Storage file doesn't exist yet, run `passage init` to create it");
    }

    let hooks_dir = hooks_dir()?;
    if fs::metadata(&hooks_dir).is_ok() {
        println!("Hooks directory: {}", hooks_dir);
    } else {
        println!("Hooks directory does not exist yet: {}", hooks_dir);
    }
    Ok(())
}

fn run_hook(hook: &Hook, event: &HookEvent) -> Result<()> {
    let path = Path::new(&hooks_dir()?)
        .join(hook.name())
        .display()
        .to_string();
    if fs::metadata(&path).is_ok() {
        println!("Running {} hook", hook.name());
        let storage_dir = storage_dir()?;
        let output = Command::new(path)
            .args(&[event.name()])
            .current_dir(storage_dir)
            .output()?;

        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;

        for line in stdout.lines() {
            println!("{}: {}", hook.name(), line);
        }
        for line in stderr.lines() {
            println!("{}: {}", hook.name(), line);
        }

        if !output.status.success() {
            anyhow!("{} hook failed", hook.name());
        }
    }

    Ok(())
}

fn keyring_check() -> Result<()> {
    let username = &whoami::username();
    let keyring = keyring::Keyring::new(KEYRING_APP_NAME, username);
    if keyring.get_password().is_err() {
        anyhow!("Failed to access password in keyring");
    }
    println!("Keyring integration seems fine");
    Ok(())
}

fn keyring_forget() -> Result<()> {
    let username = &whoami::username();
    let keyring = keyring::Keyring::new(KEYRING_APP_NAME, username);
    if keyring.delete_password().is_err() {
        anyhow!("Failed to delete password from keyring");
    }
    Ok(())
}

fn main() -> Result<(), Error> {
    let opt = Opt::from_args();
    match opt {
        Opt::New => new_entry(),
        Opt::List => list(),
        Opt::Init => init(),
        Opt::Show { entry, on_screen } => show(&entry, on_screen),
        Opt::Info => info(),
        Opt::Keyring(ko) => match ko {
            KeyringOpt::Check => keyring_check(),
            KeyringOpt::Forget => keyring_forget(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok() {
        let text = b"this is plain";
        let passphrase = Secret::new("secret".to_string());
        let encrypted = encrypt(text, passphrase.clone()).unwrap();
        let decrypted = decrypt(&encrypted, &passphrase).unwrap();
        assert_eq!(decrypted, text);
    }

    #[test]
    fn test_entry_serialization() {
        let s: Storage = toml::from_str("[foo] \n password = 'bar'").unwrap();
        assert_eq!(s.entries.get("foo").unwrap().password, "bar");
    }
}
