//! `orca completions <shell>` — generate shell completion scripts.
//!
//! Used by the installers and npm postinstall; must stay side-effect free
//! (no network, auth, tracing, or tokio).

use clap::CommandFactory as _;
use clap_complete::{Shell, generate};

use crate::app::PagerArgs;
use crate::app::cli::PUBLIC_CLI_NAME;

/// Generate and print the completion script for the given shell.
pub fn run(shell: Shell) {
    let mut cmd = PagerArgs::command().name(PUBLIC_CLI_NAME);
    if shell != Shell::Zsh {
        generate(shell, &mut cmd, PUBLIC_CLI_NAME, &mut std::io::stdout());
        return;
    }
    let mut buf = Vec::new();
    generate(shell, &mut cmd, PUBLIC_CLI_NAME, &mut buf);
    match String::from_utf8(buf) {
        Ok(script) => print!("{}", fix_zsh_root_prompt_positional(&script)),
        Err(e) => {
            use std::io::Write as _;
            let _ = std::io::stdout().write_all(e.as_bytes());
        }
    }
}

/// Work around clap_complete's broken zsh output for an optional free-form
/// positional (`[PROMPT]`) preceding the subcommand slot
/// (<https://github.com/clap-rs/clap/issues/6282>).
///
/// Drop the useless prompt slot and shift root dispatch to `$line[1]`. Nested
/// subcommand blocks already use `$line[1]` and are untouched.
fn fix_zsh_root_prompt_positional(script: &str) -> String {
    let mut out = String::with_capacity(script.len());
    script
        .lines()
        .filter(|line| !line.starts_with("'::prompt -- "))
        .for_each(|line| {
            out.push_str(line);
            out.push('\n');
        });
    let ctx_from =
        format!(r#"curcontext="${{curcontext%:*:*}}:{PUBLIC_CLI_NAME}-command-$line[2]:""#);
    let ctx_to =
        format!(r#"curcontext="${{curcontext%:*:*}}:{PUBLIC_CLI_NAME}-command-$line[1]:""#);
    for (from, to) in [
        (
            r#"words=($line[2] "${words[@]}")"#,
            r#"words=($line[1] "${words[@]}")"#,
        ),
        (ctx_from.as_str(), ctx_to.as_str()),
        (r#"case $line[2] in"#, r#"case $line[1] in"#),
    ] {
        out = out.replacen(from, to, 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zsh_script() -> String {
        let mut cmd = PagerArgs::command().name(PUBLIC_CLI_NAME);
        let mut buf = Vec::new();
        generate(Shell::Zsh, &mut cmd, PUBLIC_CLI_NAME, &mut buf);
        String::from_utf8(buf).expect("completion script is UTF-8")
    }

    #[test]
    fn zsh_completions_drop_prompt_slot_and_dispatch_on_line_1() {
        let raw = zsh_script();
        assert!(raw.contains("'::prompt -- "), "raw script has prompt slot");
        assert!(
            raw.contains("case $line[2] in"),
            "raw root dispatch on $line[2]"
        );

        let fixed = fix_zsh_root_prompt_positional(&raw);
        assert!(
            !fixed.contains("::prompt"),
            "prompt positional must not appear in the emitted zsh script"
        );
        assert!(
            !fixed.contains("$line[2]"),
            "root dispatch must be shifted to $line[1]"
        );
        let expected_ctx =
            format!(r#"curcontext="${{curcontext%:*:*}}:{PUBLIC_CLI_NAME}-command-$line[1]:""#);
        assert!(
            fixed.contains(&expected_ctx),
            "root dispatch context must use $line[1]"
        );
        assert!(
            fixed.contains(&format!("{PUBLIC_CLI_NAME}-worktree-command-$line[1]")),
            "nested subcommand dispatch must be untouched"
        );
        assert!(
            fixed.contains(&format!("_{PUBLIC_CLI_NAME}_commands")),
            "root command list intact"
        );
    }
}
