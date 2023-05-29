use clap::Parser;
use log::*;
use std::error::Error;
use std::io::stdin;
use std::io::stdout;
use std::io::ErrorKind;
use std::io::Write;
use std::net::AddrParseError;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::str;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::thread::sleep;

/// The maximum length of a username
const USERNAME_LENGTH_LIMIT: usize = 32;

/// The size of buffer to be used in the recv_from() call
const BUF_SIZE: usize = 1024;

/// The maximum length of a message a user can send
const MAX_MESSAGE_LENGTH: usize = 512;

/// The message user can type to exit the chat app
const EXIT_COMMAND: &str = "/exit";

/// The duration thread will sleep for when waiting for data (non blocking UDP socket)
const SOCKET_BLOCK_DURATION: std::time::Duration = std::time::Duration::from_millis(100);

/// Stores read-only configuration for the chat app
#[derive(Debug, Clone)]
struct ChatConfig {
    port: u16,
    local_ip: IpAddr,
    username: String,
}
/// Arguments passed to the program, read from the command line
#[derive(Parser, Debug)]
#[command(author, version, about = "A simple chat app written in Rust")]
pub struct CliArgs {
    #[arg(short, long, default_value_t = 6789, help = "Port to listen on")]
    port: u16,
}

/// Ask the user for a username
pub fn get_username() -> String {
    let mut username = String::new();
    print!("Enter a username > ");

    stdout().flush().unwrap();
    stdin()
        .read_line(&mut username)
        .expect("Failed to read username");

    let username = username.trim();
    if username.is_empty() || username.len() > USERNAME_LENGTH_LIMIT || username.contains(' ') {
        println!("Username must be between 1 and 32 characters long, with no whitespace");
        return get_username();
    }

    username.to_string()
}

/// Ask the user for the local IP address
fn read_ip_address() -> IpAddr {
    println!("Could not auto-detect local IP address. Please enter it manually.
        It looks something like 192.168.3.52. Use the ifconfig/ipconfig command to determine local-ip.");
    loop {
        let mut ip_input = String::new();
        print!("Local IP address > ");
        stdout().flush().unwrap();
        stdin()
            .read_line(&mut ip_input)
            .expect("Failed to read IP address");

        let ip: Result<IpAddr, AddrParseError> = ip_input.trim().parse();

        match ip {
            Ok(ip) => return ip,
            Err(e) => {
                warn!("Failed to parse IP address due to error {:?}", e);
                continue;
            }
        }
    }
}

/// Get the local IP address of the machine, and if that fails, read it from stdin
fn get_local_ip_address() -> Result<IpAddr, Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let arbitrary_loopback = SocketAddr::from(([1, 2, 3, 5], 6));

    if let Err(_) = socket.connect(arbitrary_loopback) {
        return Ok(read_ip_address());
    }

    let local_ip = match socket.local_addr() {
        Ok(addr) => addr.ip(),
        Err(e) => {
            warn!("Failed to auto-get local IP address due to error {:?}", e);
            read_ip_address()
        }
    };

    Ok(local_ip)
}

/// Get the broadcast IP address for the local IP address
fn get_broadcast_ip(local_ip: IpAddr) -> IpAddr {
    match local_ip {
        IpAddr::V4(ipv4) => {
            let mut octets = ipv4.octets();
            octets[3] = 255;
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
        }
        IpAddr::V6(_ipv6) => {
            panic!("IPv6 broadcast is not supported yet");
        }
    }
}

/// Create the socket that will be used for communication
fn get_chat_broadcast_socket(config: &Arc<ChatConfig>) -> Arc<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], config.port)))
        .expect("Failed to bind to socket");
    socket
        .set_nonblocking(true)
        .expect("Failed to set socket to non-blocking mode");
    socket
        .set_broadcast(true)
        .expect("Failed to set socket to broadcast mode");
    let broadcast_ip = get_broadcast_ip(config.local_ip);
    info!("Messaging socket: {socket:?}, broadcast IP: {broadcast_ip:?}");
    Arc::new(socket)
}

/// Print the prompt displayed to the user
fn display_prompt(config: &Arc<ChatConfig>) {
    println!("");
    print!("\r");
    print!("{0 } > ", config.username);
    stdout().flush().expect("Failed to flush stdout");
}

/// Parse and process received data from `origin`
fn handle_data(data: &[u8], origin: SocketAddr, config: &Arc<ChatConfig>) {
    let ip = origin.ip();
    if ip == config.local_ip {
        info!("Revd from myself, ignoring message");
        return;
    }

    print!("\r");
    let spaces: String = std::iter::repeat(' ')
        .take(config.username.len() + 3)
        .collect();
    print!("{spaces}");
    print!("\r");

    if let Ok(data) = str::from_utf8(data) {
        if let Some((username, message)) = data.split_once(' ') {
            println!("{username}: {message}");
        } else {
            info!("Invalid data received from {origin:?}");
        }
    } else {
        info!("Invalid data received from {origin:?}");
    }
    display_prompt(&config);
}

/// Broadcast message after reading from stdin to all other users using the passed socket
fn send_loop(config: Arc<ChatConfig>, socket: Arc<UdpSocket>, do_exit: Arc<AtomicBool>) {
    info!("Looping send");
    loop {
        let mut message = String::new();
        display_prompt(&config);

        stdout().flush().unwrap();
        stdin()
            .read_line(&mut message)
            .expect("Failed to read message");

        let message = message.trim();

        if message == EXIT_COMMAND {
            info!("Exiting send loop due to {EXIT_COMMAND} command");
            do_exit.store(true, Ordering::SeqCst);
            break;
        }

        if message.is_empty() {
            continue;
        }

        if message.len() > MAX_MESSAGE_LENGTH {
            println!("Message length should not exceed {MAX_MESSAGE_LENGTH}");
            continue;
        }

        let data = config.username.clone() + " " + &message;

        match socket.send_to(
            data.as_bytes(),
            SocketAddr::from((get_broadcast_ip(config.local_ip), config.port)),
        ) {
            Ok(size) => info!("Sent {} bytes", size),
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => sleep(SOCKET_BLOCK_DURATION),
            Err(err) => error!("Sending message failed due to error {:?}", err),
        }
    }
}

/// Read and handle data from the socket
fn recv_loop(config: Arc<ChatConfig>, socket: Arc<UdpSocket>, do_exit: Arc<AtomicBool>) {
    let mut buf = [0; BUF_SIZE];
    info!("Looping recv");
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, sock)) => {
                info!("recv_from read {size} bytes from {sock:?}");
                handle_data(&buf, sock, &config);
                buf[..size].fill(0);
            }
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                if do_exit.load(Ordering::SeqCst) {
                    info!("Exiting recv loop");
                    break;
                }
                sleep(SOCKET_BLOCK_DURATION);
                continue;
            }
            Err(err) => error!("recv_from failed: {:?}", err),
        }
    }
}

/// Initialize the chat application and start the send and receive loops
pub fn init(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(ChatConfig {
        port: args.port,
        local_ip: get_local_ip_address().unwrap(),
        username: get_username(),
    });

    info!("Client configuration: {:#?}", config);
    let sock = get_chat_broadcast_socket(&config);
    let sender = Arc::clone(&sock);
    let receiver = Arc::clone(&sock);
    let do_exit = Arc::new(AtomicBool::new(false));

    let send_config = Arc::clone(&config);
    let send_do_exit = Arc::clone(&do_exit);
    let recv_config = Arc::clone(&config);
    let recv_do_exit = Arc::clone(&do_exit);

    let mut join_handles = vec![];

    println!("Type {EXIT_COMMAND} to exit the application");

    join_handles.push(thread::spawn(move || {
        send_loop(send_config, sender, send_do_exit)
    }));
    join_handles.push(thread::spawn(move || {
        recv_loop(recv_config, receiver, recv_do_exit)
    }));

    for thread_handle in join_handles {
        info!("Thread {:?} joined", thread_handle.thread().id());
        thread_handle.join().expect("Failed to join thread");
    }

    println!("Exiting application.");
    Ok(())
}
