# dns-in-a-weekend

A Rust solution for ['Implement DNS in a weekend' by Julia Evans](https://implement-dns.wizardzines.com).

# Building shovel

The binary implementing DNS resolution is called `shovel`. Build it using `cargo`:
```sh
$ cargo build --release
```

# Running shovel

The syntax for running `shovel` is:
```sh
$ shovel [DOMAIN] [QTYPE] [NAMESERVER]
```

For example:
```sh
shovel twitter.com A
Querying 198.41.0.4 for twitter.com
Querying 192.12.94.30 for twitter.com
Querying 198.41.0.4 for a.r06.twtrdns.net
Querying 192.12.94.30 for a.r06.twtrdns.net
Querying 205.251.195.207 for a.r06.twtrdns.net
Querying 205.251.192.179 for twitter.com
Resolved twitter.com: 104.244.42.65
```
