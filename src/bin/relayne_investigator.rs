#[path = "../investigator/mod.rs"]
mod investigator;

fn main() -> anyhow::Result<()> {
    investigator::service::cli()
}
