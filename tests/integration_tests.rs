use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;

fn passage() -> Command {
    Command::cargo_bin("passage").unwrap()
}

/// removes the storage file so we can start clean
fn remove_entries() -> Result<()> {
    let stdout = String::from_utf8(passage().arg("info").output()?.stdout)?;
    let first_line = stdout.lines().next().unwrap();
    let storage_file = first_line.split(':').last().unwrap().trim();
    std::fs::remove_file(storage_file)?;
    Ok(())
}

#[test]
fn sanity() {
    passage()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("passage "));

    passage()
        .arg("--help")
        .assert()
        .success()
        .stdout(
            predicate::str::starts_with("passage ").and(predicate::str::contains(
                "Password manager with age encryption",
            )),
        );
}

#[test]
fn info() {
    remove_entries().unwrap_or_default();
    passage().arg("--no-keyring").arg("init").assert().success();
    passage().arg("info").assert().success().stdout(
        predicate::str::starts_with("Storage file: ").and(
            predicate::str::contains("entries.toml.age")
                .and(predicate::str::contains("\n").count(1).trim()),
        ),
    );
}

#[test]
fn new_show_list() {
    let passphrase = "master";
    let entry = "entry";
    let password = "password";

    remove_entries().unwrap_or_default();

    passage()
        .arg("--no-keyring")
        .arg("init")
        .write_stdin(format!("{}\n", passphrase))
        .assert()
        .stdout(predicate::str::starts_with("Passphrase: "))
        .success();

    passage()
        .arg("--no-keyring")
        .arg("new")
        .write_stdin(format!("{}\n{}\n{}", passphrase, entry, password))
        .assert()
        .stdout(format!("Passphrase: New entry: Password for {}: ", entry))
        .success();

    passage()
        .arg("--no-keyring")
        .arg("list")
        .write_stdin(format!("{}\n", passphrase))
        .assert()
        .stdout(format!("Enter passphrase: {}\n", entry))
        .success();

    passage()
        .arg("--no-keyring")
        .arg("show")
        .arg("--on-screen")
        .arg(entry)
        .write_stdin(format!("{}\n", passphrase))
        .assert()
        .stdout(format!("Enter passphrase: {}\n", password))
        .success();
}

#[test]
fn fail_list_no_init() {
    remove_entries().unwrap_or_default();
    passage()
        .arg("--no-keyring")
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::starts_with(
            "Error: storage not initialized, run `passage init`",
        ));
}

#[test]
fn fail_show_no_init() {
    remove_entries().unwrap_or_default();
    passage()
        .arg("--no-keyring")
        .arg("show")
        .arg("foo")
        .assert()
        .failure()
        .stderr(predicate::str::starts_with(
            "Error: storage not initialized, run `passage init`",
        ));
}

#[test]
fn fail_new_no_init() {
    remove_entries().unwrap_or_default();
    passage()
        .arg("--no-keyring")
        .arg("new")
        .assert()
        .failure()
        .stderr(predicate::str::starts_with(
            "Error: storage not initialized, run `passage init`",
        ));
}
