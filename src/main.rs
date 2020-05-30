#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::string::FromUtf8Error;

use lazy_static::lazy_static;

use secrecy::Secret;
use structopt::StructOpt;
use thiserror::Error;

lazy_static! {
    static ref STORAGE_DIR: String = {
        let home_dir: String = std::env::var("HOME").expect("env var 'HOME' is not set");
        format!("{}/.local/share/passage/entries", home_dir)
    };
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
    Show { entry: String },
}

#[derive(Error, Debug)]
enum Error {
    #[error(transparent)]
    Age(#[from] age::Error),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error("Environment variable not found")]
    VariableExpansion(#[from] std::env::VarError),

    #[error(transparent)]
    oncryption(#[from] FromUtf8Error),
}

fn encrypt(plaintext: &[u8], passphrase: String) -> Result<Vec<u8>, Error> {
    let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase));

    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted, age::Format::Binary)?;
    writer.write_all(&plaintext)?;
    writer.finish()?;

    Ok(encrypted)
}

fn decrypt(encrypted: &[u8], passphrase: String) -> Result<Vec<u8>, Error> {
    let decryptor = match age::Decryptor::new(&encrypted[..])? {
        age::Decryptor::Passphrase(d) => d,
        _ => unreachable!(),
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
    print!("Entry> ");
    io::stdout().flush()?;
    let mut entry = String::new();
    io::stdin().read_line(&mut entry)?;
    let entry = entry.trim();

    let password = rpassword::prompt_password_stdout(format!("Password for {}:", entry).as_ref())?;
    let passphrase = rpassword::prompt_password_stdout("Enter passphrase:")?;

    let encrypted = encrypt(&password.into_bytes(), passphrase)?;
    let mut file = File::create(format!("{}/{}", STORAGE_DIR.clone(), entry))?;
    file.write_all(&encrypted)?;
    Ok(())
}

fn list() -> Result<(), Error> {
    for entry in fs::read_dir(STORAGE_DIR.clone())? {
        println!(
            "{}",
            entry?.file_name().to_str().expect("Failed to decode entry")
        );
    }
    Ok(())
}

fn init() -> Result<(), Error> {
    fs::create_dir_all(Path::new(&STORAGE_DIR.clone()))?;
    Ok(())
}

fn show(entry: &str) -> Result<(), Error> {
    println!("Showing {}", entry);
    let mut encrypted: Vec<u8> = vec![];
    let file = File::open(format!("{}/{}", STORAGE_DIR.clone(), entry))?;
    let mut buf = BufReader::new(file);
    buf.read_to_end(&mut encrypted)?;
    let passphrase = rpassword::prompt_password_stdout("Enter passphrase:")?;
    let decrypted = decrypt(&encrypted, passphrase)?;
    println!("{}", String::from_utf8(decrypted)?);

    Ok(())
}

fn main() -> Result<(), Error> {
    let opt = Opt::from_args();
    match opt {
        Opt::New => new_entry(),
        Opt::List => list(),
        Opt::Init => init(),
        Opt::Show { entry } => show(&entry),
    }
}
