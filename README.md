# TLSWrap

Integrating TLS into your code can be troublesome, especially if you
don't even have access to the original source...

By using the infamous `LD_PRELOAD` trick as below, this library will wrap your

- accept
- write
- send
- recv
- read

syscalls into ones that handle TLS traffic. It handles all the handshaking and such
and you should be able to use `read` and `write` on regular files as usual.

## Usage

Build `libtlswrap.so` by running `make`

The library will search for `key.pem` and `cert.pem` in the same directory as the `.so` file.

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Then run your command with:

```bash
LD_PRELOAD=/path/to/tlswrap/libtlswrap.so yourcommand
```

You should have a TLS-enabled socket now without coding any openssl \o/
