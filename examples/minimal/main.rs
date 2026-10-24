//! The binary of the example service: `cargo run --example minimal -- help`.

mod service;

fn main() {
    mcp_starter::runtime::run_main(|args, io, getenv| service::run(args, io, getenv, None))
}
