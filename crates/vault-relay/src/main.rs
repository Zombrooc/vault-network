use std::{
    env,
    io::{self, IsTerminal, Read},
    net::TcpListener,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use vault_transport::{RelayConfig, RelayServer};

fn main() {
    let listen = match listen_address() {
        Ok(address) => address,
        Err(message) => {
            eprintln!("{message}");
            process::exit(2);
        }
    };
    let listener = TcpListener::bind(&listen).unwrap_or_else(|error| {
        eprintln!("failed to bind relay listener: {error}");
        process::exit(1);
    });
    let server = RelayServer::new(RelayConfig::default());
    let metrics = server.metrics();
    let stopping = Arc::new(AtomicBool::new(false));
    let stopping_for_handler = Arc::clone(&stopping);
    ctrlc::set_handler(move || stopping_for_handler.store(true, Ordering::Release)).unwrap_or_else(
        |error| {
            eprintln!("failed to install shutdown handler: {error}");
            process::exit(1);
        },
    );
    let handle = server.start(listener);
    println!("vault-relay listening on {listen}");
    if io::stdin().is_terminal() {
        let stopping_for_stdin = Arc::clone(&stopping);
        thread::spawn(move || {
            let mut input = String::new();
            let _ = io::stdin().read_to_string(&mut input);
            stopping_for_stdin.store(true, Ordering::Release);
        });
    }
    while !stopping.load(Ordering::Acquire) {
        thread::sleep(Duration::from_secs(1));
    }
    handle.shutdown();
    if let Err(error) = handle.join() {
        eprintln!("relay shutdown failed: {error}");
        process::exit(1);
    }
    let snapshot = metrics.snapshot();
    println!(
        "relay stopped: {} circuits closed, {} bytes forwarded",
        snapshot.closed_circuits, snapshot.forwarded_bytes
    );
}

fn listen_address() -> Result<String, String> {
    let mut args = env::args().skip(1);
    let mut listen = String::from("127.0.0.1:9000");
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--listen" => {
                listen = args
                    .next()
                    .ok_or_else(|| "missing value for --listen".to_owned())?
            }
            "-h" | "--help" => {
                println!("Usage: vault-relay [--listen ADDRESS]");
                println!("Default: 127.0.0.1:9000");
                process::exit(0);
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(listen)
}
