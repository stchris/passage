#![forbid(unsafe_code)]
#![deny(clippy::cargo)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::panic)]
#![allow(clippy::multiple_crate_versions)]

use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read, Write};

use anyhow::{anyhow, Error, Result};
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use directories::ProjectDirs;
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    name: String,
    password: String,
}

#[derive(Debug)]
struct Storage {
    entries: Vec<Entry>,
}

impl Storage {
    const fn new() -> Self {
        Self { entries: vec![] }
    }

    fn write(&self, passphrase: String) -> Result<()> {
        let buf: Vec<u8> = vec![];
        bincode::serialize_into(buf, &self.entries)?;
        let bytes = encrypt(&buf, passphrase)?;
        let mut file = File::create(format!("{}/{}", storage_dir()?.display(), "storage"))?;
        Ok(file.write_all(&bytes)?)
    }

    fn load(&mut self, passphrase: String) -> Result<()> {
        let mut buf: Vec<u8> = vec![];
        let mut file = File::create(format!("{}/{}", storage_dir()?.display(), "storage"))?;
        file.read_to_end(&mut buf)?;
        let bytes = buf.clone();
        decrypt(&bytes, passphrase)?;
        self.entries = bincode::deserialize_from(file)?;
        Ok(())
    }

    fn add(&mut self, e: Entry) {
        self.entries.push(e);
    }

    fn exists(&self, name: &str) -> bool {
        self.entries.iter().filter(|e| e.name == name).count() > 0
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
}

fn storage_dir() -> Result<std::path::PathBuf> {
    match ProjectDirs::from("", "", "passage") {
        Some(pd) => {
            let mut storage_dir = pd.data_dir().to_owned();
            storage_dir.push("entries");
            Ok(storage_dir)
        }
        None => Err(anyhow!("couldn't determine project storage folder")),
    }
}

fn encrypt(plaintext: &[u8], passphrase: String) -> Result<Vec<u8>, Error> {
    let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase));

    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted, age::Format::Binary)?;
    writer.write_all(plaintext)?;
    writer.finish()?;

    Ok(encrypted)
}

fn decrypt(encrypted: &[u8], passphrase: String) -> Result<Vec<u8>, Error> {
    let decryptor = match age::Decryptor::new(&encrypted[..])? {
        age::Decryptor::Passphrase(d) => d,
        age::Decryptor::Recipients(..) => unreachable!(),
    };

    let mut decrypted = vec![];
    let mut reader = decryptor.decrypt(&Secret::new(passphrase), None)?;
    loop {
        let bytes = reader.read_to_end(&mut decrypted)?;
        if bytes == 0 {
            break;
        }
    }

    Ok(decrypted)
}

fn new_entry() -> Result<(), Error> {
    print!("Entry: ");
    io::stdout().flush()?;
    let mut entry = String::new();
    io::stdin().read_line(&mut entry)?;
    let entry = entry.trim();

    // check if entry already exists
    for e in fs::read_dir(storage_dir()?)? {
        if e?.file_name().to_str().unwrap_or("") == entry {
            print!("'{}' already exists. Overwrite (y/N)? ", entry);
            io::stdout().flush()?;
            let mut overwrite = String::new();
            io::stdin().read_line(&mut overwrite)?;
            let overwrite = overwrite.trim();
            if overwrite.to_uppercase() != "Y" {
                return Ok(());
            }
        }
    }

    let password = rpassword::prompt_password_stdout(format!("Password for {}: ", entry).as_ref())?;
    let passphrase = rpassword::prompt_password_stdout("Passphrase: ")?;

    let encrypted = encrypt(&password.into_bytes(), passphrase)?;
    let mut file = File::create(format!("{}/{}", storage_dir()?.display(), entry))?;
    file.write_all(&encrypted)?;
    Ok(())
}

fn list() -> Result<(), Error> {
    for entry in fs::read_dir(storage_dir()?)? {
        println!(
            "{}",
            entry?.file_name().to_str().expect("Failed to decode entry")
        );
    }
    Ok(())
}

fn init() -> Result<(), Error> {
    fs::create_dir_all(storage_dir()?)?;
    Ok(())
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

fn show(entry: &str, on_screen: bool) -> Result<(), Error> {
    let mut encrypted: Vec<u8> = vec![];
    let file = File::open(format!("{}/{}", storage_dir()?.display(), entry))?;
    let mut buf = BufReader::new(file);
    buf.read_to_end(&mut encrypted)?;
    let passphrase = rpassword::prompt_password_stdout("Enter passphrase:")?;
    let decrypted = decrypt(&encrypted, passphrase)?;
    let decrypted = String::from_utf8(decrypted)?;
    if on_screen {
        println!("{}", decrypted)
    } else {
        copy_to_clipbpard(decrypted)?;
    }

    Ok(())
}

fn info() -> Result<()> {
    if storage_dir()?.exists() {
        println!("Storage folder: {}", storage_dir()?.display());
    } else {
        println!("Storage folder doesn't exist yet, run `passage init` to create it");
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_cycle() {
        let text = b"this is plain";
        let passphrase = "secret";
        let encrypted = encrypt(text, passphrase.to_string()).unwrap();
        let decrypted = decrypt(&encrypted, passphrase.to_string()).unwrap();
        assert_eq!(decrypted, text);
    }

    #[test]
    fn test_storage() {
        let mut storage = Storage::new();
        storage.add(Entry {
            name: "hello".to_string(),
            password: "world".to_string(),
        });
        assert_eq!(storage.exists("hello"), true);
    }

    #[test]
    fn test_storage_write_load() {
        let mut storage = Storage::new();
        storage.add(Entry {
            name: "123".to_string(),
            password: "123".to_string(),
        });
        storage.write("secret".to_string()).unwrap();

        let mut storage2 = Storage::new();
        storage2.load("secret".to_string()).unwrap();
        assert_eq!(storage2.exists("123"), true);
    }
}
