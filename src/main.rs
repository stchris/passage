use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read, Write};
use std::path::Path;

use lazy_static::lazy_static;
use rpassword;
use secrecy::Secret;
use structopt::StructOpt;
use thiserror::Error;

lazy_static! {
    static ref STORAGE_DIR: String = {
        let home_dir: String = std::env::var("HOME").unwrap();
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
    AgeError(#[from] age::Error),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error("Environment variable not found")]
    VariableExpansionError(#[from] std::env::VarError),
}

fn encrypt(plaintext: Vec<u8>, passphrase: String) -> Result<Vec<u8>, Error> {
    let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_owned()));

    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted, age::Format::Binary)?;
    writer.write_all(&plaintext)?;
    writer.finish()?;

    Ok(encrypted)
}

fn decrypt(encrypted: Vec<u8>, passphrase: String) -> Result<Vec<u8>, Error> {
    let decryptor = match age::Decryptor::new(&encrypted[..])? {
        age::Decryptor::Passphrase(d) => d,
        _ => unreachable!(),
    };

    let mut decrypted = vec![];
    let mut reader = decryptor.decrypt(&Secret::new(passphrase.to_owned()), None)?;
    loop {
        let bytes = reader.read_to_end(&mut decrypted).unwrap();
        if bytes == 0 {
            break;
        }
    }

    Ok(decrypted)
}

fn new_entry() -> Result<(), Error> {
    print!("Entry> ");
    io::stdout().flush().unwrap();
    let mut entry = String::new();
    io::stdin().read_line(&mut entry).unwrap();
    let entry = entry.trim();

    let password =
        rpassword::prompt_password_stdout(format!("Password for {}:", entry).as_ref()).unwrap();
    let passphrase = rpassword::prompt_password_stdout("Enter passphrase:").unwrap();

    match encrypt(password.into_bytes(), passphrase) {
        Ok(encrypted) => {
            let mut file = File::create(format!("{}/{}", STORAGE_DIR.clone(), entry)).unwrap();
            file.write_all(&encrypted).unwrap();
        }
        Err(err) => panic!(err),
    };
    Ok(())
}

fn list() -> Result<(), Error> {
    for entry in fs::read_dir(STORAGE_DIR.clone())? {
        println!("{}", entry.unwrap().file_name().to_str().unwrap());
    }
    Ok(())
}

fn init() -> Result<(), Error> {
    fs::create_dir_all(Path::new(&STORAGE_DIR.clone()))?;
    Ok(())
}

fn show(entry: String) -> Result<(), Error> {
    println!("Showing {}", entry);
    let mut encrypted: Vec<u8> = vec![];
    let file = File::open(format!("{}/{}", STORAGE_DIR.clone(), entry)).unwrap();
    let mut buf = BufReader::new(file);
    buf.read_to_end(&mut encrypted).unwrap();
    let passphrase = rpassword::prompt_password_stdout("Enter passphrase:").unwrap();
    let decrypted = decrypt(encrypted, passphrase).unwrap();
    println!("{}", String::from_utf8(decrypted).unwrap());

    Ok(())
}

fn main() -> Result<(), Error> {
    let opt = Opt::from_args();
    match opt {
        Opt::New => new_entry(),
        Opt::List => list(),
        Opt::Init => init(),
        Opt::Show { entry } => show(entry),
    }
}
