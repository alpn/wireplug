use std::process::Stdio;

use tokio::process;

// XXX
pub async fn add_relays(relays: &Vec<Relay>) {
    let mut child = process::Command::new("pfctl")
        .arg("-F")
        .arg("state")
        .arg("-a")
        .arg("wp_relays")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    if let Some(stdin) = child.stdin.as_mut() {
        for relay in relays {
            relay.write_rules(stdin);
        }
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow::Error::msg("could not set pf rules"));
    }
}
