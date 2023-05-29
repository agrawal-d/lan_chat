# Lan Chat

A text-messaging application implemented in Rust that does not require a
server for clients to communicate. Requires zero config to get started -
no need to mess with IPs, ports etc. Just run and start messaging.

## How it works?

The application works by using non-blocking UDP sockets to communicate
by broadcasting messages on the local IP address, that the application tries
to auto detect.

## License

```
Lan Chat - zero config serverless chat application.
Copyright (C) 2023 Divyanshu Agrawal

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```
