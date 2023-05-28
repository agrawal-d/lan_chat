use clap::Parser;
use log::*;
use std::error::Error;
use std::io::stdin;
use std::io::stdout;
use std::io::Write;
use std::net::AddrParseError;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::str;
use std::sync::Arc;
use std::thread;

const USERNAME_LENGTH_LIMIT: usize = 32;
const BUF_SIZE: usize = 1024;
const MAX_MESSAGE_LENGTH: usize = 512;

#[derive(Debug, Clone)]
struct ChatConfig {
    port: u16,
    local_ip: IpAddr,
    username: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "A simple chat app written in Rust")]
pub struct CliArgs {
    #[arg(short, long, default_value_t = 6789, help = "Port to listen on")]
    port: u16,
}

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

fn get_send_socket(config: &Arc<ChatConfig>) -> Arc<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], config.port)))
        .expect("Failed to bind to socket");
    socket
        .set_broadcast(true)
        .expect("Failed to set socket to broadcast mode");
    let broadcast_ip = get_broadcast_ip(config.local_ip);
    info!("Messaging socket: {socket:?}, broadcast IP: {broadcast_ip:?}");
    Arc::new(socket)
}
fn display_prompt(config: &Arc<ChatConfig>) {
    println!("");
    print!("\r");
    print!("{0 } > ", config.username);
    stdout().flush().expect("Failed to flush stdout");
}

fn handle_data(data: &[u8], origin: SocketAddr, config: &Arc<ChatConfig>) {
    let ip = origin.ip();
    if ip == config.local_ip {
        info!("Revd from myself");
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

fn send_loop(config: Arc<ChatConfig>, socket: Arc<UdpSocket>) {
    info!("Looping send");
    loop {
        let mut message = String::new();
        display_prompt(&config);

        stdout().flush().unwrap();
        stdin()
            .read_line(&mut message)
            .expect("Failed to read message");

        let message = message.trim();

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
            Err(err) => error!("Sending message failed due to error {:?}", err),
        }
    }
}

fn recv_loop(config: Arc<ChatConfig>, socket: Arc<UdpSocket>) {
    let mut buf = [0; BUF_SIZE];
    info!("Looping recv");
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, sock)) => {
                info!("recv_from read {size} bytes from {sock:?}");
                handle_data(&buf, sock, &config);
                buf[..size].fill(0);
            }
            Err(err) => error!("recv_from failed: {:?}", err),
        }
    }
}

pub fn init(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(ChatConfig {
        port: args.port,
        local_ip: get_local_ip_address().unwrap(),
        username: get_username(),
    });

    info!("Client configuration: {:#?}", config);
    let sock = get_send_socket(&config);
    let sender = Arc::clone(&sock);
    let receiver = Arc::clone(&sock);

    let send_config = Arc::clone(&config);
    let recv_config = Arc::clone(&config);

    let mut threads = vec![];

    threads.push(thread::spawn(move || send_loop(send_config, sender)));
    threads.push(thread::spawn(move || recv_loop(recv_config, receiver)));

    for thread in threads {
        thread.join().expect("Failed to join thread");
    }

    Ok(())
}
