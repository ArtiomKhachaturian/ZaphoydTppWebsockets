#include "LocalEchoServer.h"

namespace Tests
{

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

LocalEchoServer::LocalEchoServer()
{
    _server.clear_access_channels(websocketpp::log::alevel::all);
    _server.clear_error_channels(websocketpp::log::elevel::all);
}

LocalEchoServer::~LocalEchoServer()
{
    stop();
}

void LocalEchoServer::start()
{
    if (!_running.exchange(true)) {
        _server.init_asio();
        _server.set_reuse_addr(true);
        _server.set_message_handler(bind(&LocalEchoServer::onMessage, this, _1, _2));

        const websocketpp::lib::asio::ip::tcp::endpoint ep(
            websocketpp::lib::asio::ip::make_address("127.0.0.1"), 0U);
        websocketpp::lib::error_code ec;
        _server.listen(ep, ec);
        if (ec) {
            _running = false;
            throw websocketpp::exception("LocalEchoServer::listen failed: " + ec.message(),
                                         websocketpp::error::general);
        }

        websocketpp::lib::asio::error_code localEc;
        _port = _server.get_local_endpoint(localEc).port();

        _server.start_accept();
        _thread = std::thread([this]() {
            try {
                _server.run();
            }
            catch (...) {
                // server is shutting down (stop()/destructor) or hit a transport
                // error; nothing test-relevant to do with it here.
            }
        });
    }
}

void LocalEchoServer::stop()
{
    if (_running.exchange(false)) {
        try {
            _server.stop_listening();
        }
        catch (...) {
        }
        _server.stop();
        if (_thread.joinable()) {
            _thread.join();
        }
    }
}

std::string LocalEchoServer::url() const
{
    return "ws://127.0.0.1:" + std::to_string(_port);
}

void LocalEchoServer::onMessage(websocketpp::connection_hdl hdl, MessagePtr message)
{
    if (message) {
        try {
            _server.send(hdl, message->get_payload(), message->get_opcode());
        }
        catch (const websocketpp::exception&) {
            // ignore send failures during test teardown races
        }
    }
}

} // namespace Tests
