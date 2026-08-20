#pragma once // LocalEchoServer.h
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

namespace Tests
{

// Minimal plaintext (ws://) echo server used to exercise Tpp::EndPoint end to
// end from tests, without depending on a real remote server. Listens on an
// OS-assigned loopback-only port and echoes every text/binary frame back
// verbatim; PING frames are answered with PONG automatically by websocketpp
// itself. Modeled on websocketpp's own examples/echo_server/echo_server.cpp.
class LocalEchoServer
{
public:
    LocalEchoServer();
    ~LocalEchoServer();

    LocalEchoServer(const LocalEchoServer&) = delete;
    LocalEchoServer& operator = (const LocalEchoServer&) = delete;

    void start();
    void stop();
    std::string url() const;

private:
    using Server = websocketpp::server<websocketpp::config::asio>;
    using MessagePtr = Server::message_ptr;

    void onMessage(websocketpp::connection_hdl hdl, MessagePtr message);

private:
    Server _server;
    std::thread _thread;
    uint16_t _port = 0U;
    std::atomic_bool _running = false;
};

} // namespace Tests
