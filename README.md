# Lan Chat

A text-messaging application implemented in Rust that does not require a
server for clients to communicate. Requires zero config to get started -
no need to mess with IPs, ports etc. Just run and start messaging.

## How it works?

The application works by using non-blocking UDP sockets to communicate
by broadcasting messages on the local IP address, that the application tries
to auto detect.
