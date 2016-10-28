TLSSocket
=========

Usage
-----
There is an example app in `TestApp.scala`, which will start a server on port 9099:

* `sbt io/run` starts an echo server
* `sbt "io/run print"` starts a print-server, a server that doesn't read anything from the client, but writes two chunks and exits.

One easy way to connect is using `gnu-tls`:

`gnutls-cli localhost --port 9099 --no-ca-verification -vv`

The print-server disconnects automatically, for the echo server try `Ctrl-D` from `gnu-tls` to exit cleanly. A `Ctrl-C` should cause a `javax.net.ssl.SSLException: Inbound closed before receiving peer's close_notify: possible truncation attack?` exception.

Todo
----

* Write more tests and fix everything that the tests expose as broken. At least:
  - Clients and servers that only read, or only write
  - Clients and servers that concurrently read and write
  - Clients and servers that want to obtain the Certificate chain before they read or write.
  - Re-handshakes, especially during concurrent reading and writing
* Look at the many TODO's in the code
* Start handshaking as soon as the TCPSocket is created
* Implement proper closing of the connection and test resource cleanup
* Think about closing the connection properly when we hit a timeout. Suppose we're an echo server, and we have a timeout of 10 seconds. If after 10 seconds the client didn't send anything, we may want to close the connection cleanly; for that we have to close the SSLEngine, wrap some more and write the remaining netdata. This will also take time. We could add this timeout as a config parameter, but that would mean that if a user does tlssocket.read(1024, 5.seconds), and the config also allows 5 seconds for closing the connection properly, the user may need to wait 10 seconds before this actually times out. Is that what we want?
