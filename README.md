# libzstream
Tiny HTTP library based on old OWRT libzstream
Its objective is build a small footprint HTTP client library in C, using timeouted sockets.
It links against OpenSSL (1.0.2g version or higher must be used) to perform HTTPS connections.
It can be linked against OpenWRT libubox to use usock and list features. Otherwise the libubox needed code is provided in builtin folder

Compile:
make LIBUBOX=builtin

Documentation:

The project builts a doxygen format documentation

doxygen doxygen_file

TODOs:
- Set multiple values for a header tag.
- Remove a header by tag.
- Chunk trailer support.
- Send a chunked message.
