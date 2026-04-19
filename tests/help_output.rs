use assert_cmd::Command;
use predicates::prelude::*;

fn cctx() -> Command {
    Command::cargo_bin("cctx").unwrap()
}

#[test]
fn help_lists_all_subcommands() {
    cctx()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("switch"))
        .stdout(predicates::str::contains("current"))
        .stdout(predicates::str::contains("add"))
        .stdout(predicates::str::contains("delete"))
        .stdout(predicates::str::contains("doctor"))
        .stdout(predicates::str::contains("completions"));
}

#[test]
fn switch_help_exits_0() {
    cctx().args(["switch", "--help"]).assert().success();
}

#[test]
fn add_help_mentions_oauth() {
    cctx()
        .args(["add", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("oauth").or(predicates::str::contains("--oauth")));
}

#[test]
fn doctor_help_lists_flags() {
    cctx()
        .args(["doctor", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--dry-run"))
        .stdout(predicates::str::contains("--rollback"))
        .stdout(predicates::str::contains("--commit"));
}
