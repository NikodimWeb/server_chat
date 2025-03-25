### Multithreaded server-side chat.

Features:
- Server Connection
- Raising a Redis database
- Accepts messages from multiple clients via sockets.
- Processes clients in different threads.
- Sends received messages to all connected clients.
- Provides correct closing of connections when a client disconnects.
- Sending messages.
- Receives and displays messages from other clients.
- Uses std::thread multithreading.
- Has simple processing of commands (list, exit).
- It has the possibility of registration.
- Logs server events.
- There is traffic encryption using OpenSSL.

### How to use:
- Generate a certificate.
- Start the Redis database.
- Start the server.
- Next, start the client and register, then log in to your account and chat.
