#[cfg(test)]
#[path = "../team_client.rs"]
mod team_client;
#[path = "../team_server.rs"]
mod team_server;
#[path = "../ticket_escalation.rs"]
mod ticket_escalation;
#[path = "../ticket_intake.rs"]
mod ticket_intake;
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("escalation-worker") if args.len() == 2 => {
            let config = ticket_escalation::Config::from_env()?
                .ok_or_else(|| anyhow::anyhow!("Escalation is not configured"))?;
            let mut db = team_server::open_store(std::path::Path::new(&args[1]))?;
            let count = ticket_escalation::worker(&mut db, &config)?;
            println!(
                "Processed {count} authorized escalation attempts. Inspect the queue for delivery evidence."
            );
        }
        Some("bootstrap") if args.len() == 3 => {
            let issued = team_server::bootstrap(std::path::Path::new(&args[1]), &args[2])?;
            println!(
                "Admin token ID: {}\nBearer token (shown once): {}",
                issued.id, issued.token
            );
        }
        Some("serve") if (2..=3).contains(&args.len()) => {
            team_server::run(
                std::path::Path::new(&args[1]),
                args.get(2).map(String::as_str).unwrap_or("127.0.0.1:47831"),
            )?;
        }
        _ => anyhow::bail!(
                "Usage: relayne_team bootstrap <database> <admin-name> | serve <database> [bind-address:port] | escalation-worker <database>. Remote access requires a TLS reverse proxy."
        ),
    }
    Ok(())
}
