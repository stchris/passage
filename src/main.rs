use std::fs::File;
use std::io::{stdin, stdout, Read, Write};

use rpassword;
use secrecy::Secret;
use structopt::StructOpt;
use thiserror::Error;

#[derive(Debug, StructOpt)]
#[structopt(name = "passage", about = "Password manager with age encryption")]
enum Opt {
    New,
    List,
}

#[derive(Error, Debug)]
enum Error {
    #[error(transparent)]
    AgeError(#[from] age::Error),

    #[error(transparent)]
    IOError(#[from] std::io::Error),
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

fn new_entry() {
    print!("Entry> ");
    stdout().flush().unwrap();
    let mut entry = String::new();
    stdin().read_line(&mut entry).unwrap();

    let password = b"Hello world!";
    let passphrase = rpassword::prompt_password_stdout("Password:").unwrap();

    match encrypt(password.to_vec(), passphrase) {
        Ok(encrypted) => {
            let mut file = File::create("foo.txt").unwrap();
            file.write_all(&encrypted).unwrap();
        }
        Err(err) => panic!(err),
    };
}

fn list() {}

fn main() {
    let opt = Opt::from_args();
    match opt {
        Opt::New => new_entry(),
        Opt::List => list(),
    }
}