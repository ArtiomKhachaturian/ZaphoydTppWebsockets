# ZaphoydTppWebsockets

**ZaphoydTppWebsockets** is a minimal C++ WebSocket client wrapper library using the [websocketpp](https://github.com/zaphoyd/websocketpp) library.  
It demonstrates how to implement a simple WebSocket client with `standalone Asio` (no Boost dependency) and can be used as a base for integration into other C++ applications.

## Features

- Lightweight WebSocket client using `websocketpp`
- Supports both `ws://` and `wss://` connections (non-TLS and TLS)
- Text and binary message support
- Based on `standalone Asio` for minimal dependencies
- Clean and compact codebase
- Thread safety
- CMake-based build system

## Requirements

- C++20 or newer (C++17 for Unix systems)
- CMake 3.29+
- A C++ compiler (GCC, Clang, MSVC)
- [websocketpp](https://github.com/zaphoyd/websocketpp)
- [Asio (standalone)](https://think-async.com/Asio/) — or Boost.Asio (with minor changes)
- [OpenSSL](https://openssl-library.org/source/) (for `wss://` support)

## Building

Clone the repository and build using CMake:

```bash
git clone --recurse-submodules https://github.com/ArtiomKhachaturian/ZaphoydTppWebsockets.git
cd ZaphoydTppWebsockets
mkdir build && cd build
cmake ..
make
```

## Notes

- Supports both text and binary WebSocket messages.
- TLS (`wss://`) requires OpenSSL and proper certificate setup.

## License

This project is licensed under the Apache License License. See the [LICENSE](LICENSE) file for details.

## Author

[Artiom Khachaturian](https://github.com/ArtiomKhachaturian)
