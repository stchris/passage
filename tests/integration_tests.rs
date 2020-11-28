use assert_cmd::Command;
use predicates::prelude::*;

fn passage() -> Command {
    Command::cargo_bin("passage").unwrap()
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
    passage().arg("init").assert().success();
    passage().arg("info").assert().success().stdout(
        predicate::str::starts_with("Storage file: ").and(
            predicate::str::contains("entries.toml.age")
                .and(predicate::str::contains("\n").count(1).trim()),
        ),
    );
}
