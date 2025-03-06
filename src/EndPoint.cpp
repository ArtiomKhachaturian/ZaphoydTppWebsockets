// Copyright 2025 Artiom Khachaturian
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "EndPoint.h"
#include "Config.h"
#include "Api.h"
#include "Extensions.h"
#include "Listeners.h"
#include "MessageBlob.h"
#include "ServiceProvider.h"
#include "WebsocketListener.h"
#include "WebsocketError.h"
#include "WebsocketState.h"
#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>
#include <websocketpp/close.hpp>
#include <atomic>

namespace {

template<class TException, Websocket::Failure failure = Websocket::Failure::General>
inline Websocket::Error makeError(const TException& e) {
    return Websocket::Error{failure, e.code(), e.what()};
}

class LogStream : public LoggableS<std::streambuf>
{
public:
    LogStream(LoggingSeverity severity, const std::shared_ptr<Logger>& logger);
    ~LogStream() final;
    operator std::ostream* () { return &_output; }
    // overrides of std::streambuf
    std::streamsize xsputn(const char* s, std::streamsize count) final;
    int sync() final;
private:
    void sendBufferToLog();
private:
    const LoggingSeverity _severity;
    std::ostream _output;
    ProtectedObj<std::string, std::mutex> _logBuffer;
};

const std::string_view g_logCategory("WebsocketTPP");

}

namespace Tpp
{

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;
using namespace websocketpp::config;
using Hdl = websocketpp::connection_hdl;

template<class TClientType>
class EndPoint::Impl : public Api
{
    using Client = websocketpp::client<ReadBufferExtension<_readBufferSize, TClientType>>;
    using Message = typename TClientType::message_type;
    using MessagePtr = typename Message::ptr;
    using MessageBlobImpl = MessageBlob<MessagePtr>;
public:
    ~Impl() override;
    // impl. of WebsocketTppApi
    bool open() final;
    std::string host() const final { return hostRef(); }
    Websocket::State state() const final { return _state; }
    bool sendBinary(const std::shared_ptr<Blob>& binary) final;
    bool sendText(std::string_view text) final;
    void destroy() final;
protected:
    Impl(uint64_t socketId, 
         uint64_t connectionId,
         Config config,
         const std::shared_ptr<Websocket::Listener>& listener,
         const std::shared_ptr<ServiceProvider>& serviceProvider,
         const std::shared_ptr<Logger>& logger) noexcept(false);
    uint64_t socketId() const noexcept { return _socketId; }
    uint64_t connectionId() const noexcept { return _connectionId; }
    const auto& hostRef() const noexcept { return options()._host; }
    const auto& options() const noexcept { return _config.options(); }
    const auto& serviceProvider() const noexcept { return _serviceProvider; }
    const auto& client() const noexcept { return _client; }
    auto& client() noexcept { return _client; }
    void notifyAboutError(const Websocket::Error& error);
    void notifyAboutError(Websocket::Failure type, const websocketpp::exception& error);
    void notifyAboutError(Websocket::Failure type, const SysError& error);
    void notifyAboutError(Websocket::Failure type, std::error_code ec,
                          std::string_view details = "");
    template <class TOption>
    void setOption(const TOption& option, const Hdl& hdl);
    template <class TOption, typename T>
    void maybeSetOption(const std::optional<T>& value, const Hdl& hdl);
private:
    static std::string toText(MessagePtr message);
    static MessagePtr toMessage(std::string_view text);
    static MessagePtr toMessage(const std::shared_ptr<Blob>& binary);
    static std::string formatLoggerId(uint64_t id);
    bool active() const noexcept { return !_destroyed; }
    // return true if state changed
    bool setState(Websocket::State state);
    bool setState(websocketpp::session::state::value state);
    bool updateState();
    void setHdl(const Hdl& hdl);
    Hdl hdl() const;
    // handlers
    void onInit(const Hdl& hdl);
    void onFail(const Hdl& hdl);
    void onOpen(const Hdl& hdl);
    void onMessage(const Hdl& hdl, MessagePtr message);
    void onClose(const Hdl& hdl);
private:
    static constexpr auto _text = websocketpp::frame::opcode::value::text;
    static constexpr auto _binary = websocketpp::frame::opcode::value::binary;
    static constexpr uint16_t _closeCode = Websocket::CloseCode::Normal;
    const uint64_t _socketId;
    const uint64_t _connectionId;
    const Config _config;
    const std::shared_ptr<Websocket::Listener> _listener;
    const std::shared_ptr<ServiceProvider> _serviceProvider;
    Client _client;
    LogStream _errorLogStream;
    LogStream _accessLogStream;
    ProtectedObj<Hdl> _hdl;
    std::atomic<Websocket::State> _state = Websocket::State::Disconnected;
    std::atomic_bool _destroyed = false;
};

class EndPoint::TlsOn : public Impl<asio_tls_client>
{
public:
    TlsOn(uint64_t id, uint64_t connectionId, Config config,
          const std::shared_ptr<Websocket::Listener>& listener,
          const std::shared_ptr<ServiceProvider>& serviceProvider,
          const std::shared_ptr<Logger>& logger) noexcept(false);
    ~TlsOn() final;
private:
    std::shared_ptr<SSLCtx> onInitTls(const Hdl&);
};

class EndPoint::TlsOff : public Impl<asio_client>
{
public:
    TlsOff(uint64_t id, uint64_t connectionId, Config config,
           const std::shared_ptr<Websocket::Listener>& listener,
           const std::shared_ptr<ServiceProvider>& serviceProvider,
           const std::shared_ptr<Logger>& logger) noexcept(false);
};

class EndPoint::Listener : public Websocket::Listener
{
public:
    Listener() = default;
    void add(Websocket::Listener* listener) { _listeners.add(listener); }
    void remove(Websocket::Listener* listener) { _listeners.remove(listener); }
    // impl. of WebsocketListener
    void onStateChanged(uint64_t socketId, uint64_t connectionId,
                        Websocket::State state) final;
    void onError(uint64_t socketId, uint64_t connectionId,
                 const Websocket::Error& error) final;
    void onTextMessage(uint64_t socketId, uint64_t connectionId,
                       const std::string_view& message) final;
    void onBinaryMessage(uint64_t socketId, uint64_t connectionId,
                         const std::shared_ptr<Blob>& message) final;
private:
    Listeners<Websocket::Listener*> _listeners;
};

EndPoint::EndPoint(std::shared_ptr<ServiceProvider> serviceProvider,
                   const std::shared_ptr<Logger>& logger)
    : LoggableS<Websocket::EndPoint>(logger)
    , _serviceProvider(std::move(serviceProvider))
    , _listener(std::make_shared<Listener>())
{
    assert(_serviceProvider); // service provider must not be null
}

EndPoint::~EndPoint()
{
    close();
}

void EndPoint::addListener(Websocket::Listener* listener)
{
    _listener->add(listener);
}

void EndPoint::removeListener(Websocket::Listener* listener)
{
    _listener->remove(listener);
}

bool EndPoint::open(Websocket::Options options, uint64_t connectionId)
{
    bool ok = false;
    LOCK_WRITE_PROTECTED_OBJ(_impl);
    if (!_impl.constRef() ||Websocket::State::Disconnected == _impl.constRef()->state()) {
        auto impl = createImpl(std::move(options), connectionId);
        if (impl && impl->open()) {
            _impl = std::move(impl);
            ok = true;
        }
    }
    else { // connected or connecting now
        ok = true;
    }
    return ok;
}

void EndPoint::close()
{
    std::shared_ptr<Api> impl;
    {
        LOCK_WRITE_PROTECTED_OBJ(_impl);
        impl = _impl.take();
    }
    impl.reset();
}

std::string EndPoint::host() const
{
    LOCK_READ_PROTECTED_OBJ(_impl);
    if (const auto& impl = _impl.constRef()) {
        return impl->host();
    }
    return {};
}

Websocket::State EndPoint::state() const
{
    LOCK_READ_PROTECTED_OBJ(_impl);
    if (const auto& impl = _impl.constRef()) {
        return impl->state();
    }
    return Websocket::State::Disconnected;
}

bool EndPoint::sendBinary(const std::shared_ptr<Blob>& binary)
{
    LOCK_READ_PROTECTED_OBJ(_impl);
    if (const auto& impl = _impl.constRef()) {
        return impl->sendBinary(binary);
    }
    return false;
}

bool EndPoint::sendText(std::string_view text)
{
    LOCK_READ_PROTECTED_OBJ(_impl);
    if (const auto& impl = _impl.constRef()) {
        return impl->sendText(text);
    }
    return false;
}

std::shared_ptr<Api> EndPoint::createImpl(Websocket::Options options,
                                          uint64_t connectionId) const
{
    if (auto config = Config::create(std::move(options))) {
        try {
            std::unique_ptr<Api> impl;
            if (config.secure()) {
                impl = std::make_unique<TlsOn>(id(), connectionId, std::move(config),
                                               _listener, _serviceProvider, logger());
            }
            else {
                impl = std::make_unique<TlsOff>(id(), connectionId, std::move(config),
                                                _listener, _serviceProvider, logger());
            }
            return std::shared_ptr<Api>(impl.release(), [](auto* impl) { impl->destroy(); });
        }
        catch(const websocketpp::exception& e) {
            _listener->onError(id(), connectionId, makeError(e));
        }
        catch (const SysError& e) {
            _listener->onError(id(), connectionId, makeError(e));
        }
    }
    return nullptr;
}

template <class TClientType>
EndPoint::Impl<TClientType>::Impl(uint64_t socketId, uint64_t connectionId,
                                  Config config,
                                  const std::shared_ptr<Websocket::Listener>& listener,
                                  const std::shared_ptr<ServiceProvider>& serviceProvider,
                                  const std::shared_ptr<Logger>& logger) noexcept(false)
    : _socketId(socketId)
    , _connectionId(connectionId)
    , _config(std::move(config))
    , _listener(listener)
    , _serviceProvider(serviceProvider)
    , _errorLogStream(LoggingSeverity::Error, logger)
    , _accessLogStream(LoggingSeverity::Verbose, logger)
{
    // Initialize ASIO
    _client.set_user_agent(options()._userAgent);
    _client.get_elog().set_ostream(_errorLogStream);
    _client.get_alog().set_ostream(_accessLogStream);
    _client.init_asio(_serviceProvider->service());
    // Register our handlers
    _client.set_socket_init_handler(bind(&Impl::onInit, this, _1));
    _client.set_message_handler(bind(&Impl::onMessage, this, _1, _2));
    _client.set_open_handler(bind(&Impl::onOpen, this, _1));
    _client.set_close_handler(bind(&Impl::onClose, this, _1));
    _client.set_fail_handler(bind(&Impl::onFail, this, _1));
    _client.start_perpetual();
    _serviceProvider->startService();
    
}

template <class TClientType>
EndPoint::Impl<TClientType>::~Impl()
{
    _client.set_socket_init_handler(nullptr);
    _client.set_message_handler(nullptr);
    _client.set_open_handler(nullptr);
    _client.set_fail_handler(nullptr);
    _client.set_close_handler(nullptr);
    _client.stop_perpetual();
    _serviceProvider->stopService();
}

template <class TClientType>
bool EndPoint::Impl<TClientType>::open()
{
    websocketpp::lib::error_code ec;
    const auto connection = _client.get_connection(_config, ec);
    if (ec) {
        notifyAboutError(Websocket::Failure::NoConnection, ec);
    }
    else {
        const auto& extraHeaders = options()._extraHeaders;
        for (auto it = extraHeaders.begin(); it != extraHeaders.end(); ++it) {
            try {
                connection->append_header(it->first, it->second);
            }
            catch(const websocketpp::exception& e) {
                notifyAboutError(Websocket::Failure::CustomHeader, e);
                return false;
            }
            catch (const SysError& e) {
                notifyAboutError(Websocket::Failure::CustomHeader, e);
                return false;
            }
        }
        _client.connect(connection);
    }
    return !ec;
}

template <class TClientType>
bool EndPoint::Impl<TClientType>::sendText(std::string_view text)
{
    if (active()) {
        try {
            _client.send(hdl(), toMessage(text));
            return true;
        }
        catch (const websocketpp::exception& e) {
            notifyAboutError(Websocket::Failure::WriteText, e);
        }
        catch (const SysError& e) {
            notifyAboutError(Websocket::Failure::WriteText, e);
        }
    }
    return false;
}

template <class TClientType>
bool EndPoint::Impl<TClientType>::sendBinary(const std::shared_ptr<Blob>& binary)
{
    if (active()) {
        try {
            _client.send(hdl(), toMessage(binary));
            return true;
        }
        catch (const websocketpp::exception& e) {
            notifyAboutError(Websocket::Failure::WriteBinary, e);
        }
        catch (const SysError& e) {
            notifyAboutError(Websocket::Failure::WriteBinary, e);
        }
    }
    return false;
}

template <class TClientType>
void EndPoint::Impl<TClientType>::destroy()
{
    if (!_destroyed.exchange(true)) {
        setState(Websocket::State::Disconnecting);
        {
            LOCK_WRITE_PROTECTED_OBJ(_hdl);
            auto hdl = _hdl.take();
            if (!hdl.expired()) {
                try {
                    const auto reason = websocketpp::close::status::get_string(_closeCode);
                    // instance will be destroyed in [OnClose] handler
                    _client.close(hdl, _closeCode, reason);
                    setState(Websocket::State::Disconnected); // force
                    return;
                }
                catch (const std::exception& e) {
                    // ignore of failures during closing
                    _client.set_close_handler(nullptr);
                }
            }
        }
        setState(Websocket::State::Disconnected);
        delete this;
    }
}

template <class TClientType>
void EndPoint::Impl<TClientType>::notifyAboutError(const Websocket::Error& error)
{
    if (_errorLogStream.canLogError()) {
        _errorLogStream.logError(toString(error), g_logCategory);
    }
    _listener->onError(socketId(), connectionId(), error);
}

template <class TClientType>
void EndPoint::Impl<TClientType>::notifyAboutError(Websocket::Failure type,
                                                   const websocketpp::exception& error)
{
    notifyAboutError(type, error.code(), error.what());
}

template <class TClientType>
void EndPoint::Impl<TClientType>::notifyAboutError(Websocket::Failure type,
                                                   const SysError& error)
{
    notifyAboutError(type, error.code(), error.what());
}

template <class TClientType>
void EndPoint::Impl<TClientType>::notifyAboutError(Websocket::Failure type,
                                                   std::error_code ec,
                                                   std::string_view details)
{
    Websocket::Error error;
    error._failure = type;
    error._code = std::move(ec);
    error._details.assign(details.data(), details.size());
    notifyAboutError(error);
}

template <class TClientType>
template <class TOption>
void EndPoint::Impl<TClientType>::setOption(const TOption& option, const Hdl& hdl)
{
    if (!hdl.expired()) {
        try {
            if (const auto connection = _client.get_con_from_hdl(hdl)) {
                connection->get_socket().lowest_layer().set_option(option);
            }
        }
        catch (const websocketpp::exception& e) {
            notifyAboutError(Websocket::Failure::SocketOption, e);
        }
        catch (const SysError& e) {
            notifyAboutError(Websocket::Failure::SocketOption, e);
        }
    }
}

template <class TClientType>
template <class TOption, typename T>
void EndPoint::Impl<TClientType>::maybeSetOption(const std::optional<T>& value,
                                                     const Hdl& hdl)
{
    if (value) {
        setOption(ValueToOption<TOption, T>::convert(value.value()), hdl);
    }
}

template <class TClientType>
std::string EndPoint::Impl<TClientType>::toText(MessagePtr message)
{
    if (message) {
        auto text = std::move(message->get_raw_payload());
        message->recycle();
        return text;
    }
    return std::string();
}

template <class TClientType>
typename EndPoint::Impl<TClientType>::MessagePtr
    EndPoint::Impl<TClientType>::toMessage(std::string_view text)
{
    auto message = std::make_shared<Message>(nullptr, _text, 0U);
    if (!text.empty()) {
        message->get_raw_payload() = std::string(text.data(), text.size());
    }
    return message;
}

template <class TClientType>
typename EndPoint::Impl<TClientType>::MessagePtr
    EndPoint::Impl<TClientType>::toMessage(const std::shared_ptr<Blob>& binary)
{
    auto message = std::make_shared<Message>(nullptr, _binary, 0U);
    if (binary) {
        // overhead - deep copy of input buffer,
        // Websocketpp doesn't supports of buffers abstraction,
        // workarounds with custom allocator for payload std::string doesn't works:
        //  - allocation size which is passed to [allocate] method is
        //    always greater than buffer capacity (penalty of std::string internals)
        //  - resize operation (until C++23) erases buffer data,
        //    at least we need [resize_and_overwrite]: https://en.cppreference.com/w/cpp/string/basic_string/resize_and_overwrite
        // TODO: possible solution -> make a fork of Websocket TPP repo and replace std::string to buffer abstraction
        auto& payload = message->get_raw_payload();
        const auto data = reinterpret_cast<const char*>(binary->data());
        payload.assign(data, binary->size());
    }
    return message;
}


template <class TClientType>
std::string EndPoint::Impl<TClientType>::formatLoggerId(uint64_t id)
{
    return "WebsocketTpp (id #" + std::to_string(id) + ")";
}

template <class TClientType>
bool EndPoint::Impl<TClientType>::setState(Websocket::State state)
{
    if (state != _state.exchange(state)) {
        _listener->onStateChanged(socketId(), connectionId(), state);
        return true;
    }
    return false;
}

template <class TClientType>
bool EndPoint::Impl<TClientType>::setState(websocketpp::session::state::value state)
{
    switch (state) {
        case websocketpp::session::state::connecting:
            return setState(Websocket::State::Connecting);
        case websocketpp::session::state::open:
            return setState(Websocket::State::Connected);
        case websocketpp::session::state::closing:
            return setState(Websocket::State::Disconnecting);
        case websocketpp::session::state::closed:
            return setState(Websocket::State::Disconnected);
        default:
            assert(false); // unknown state
            break;
    }
    return false;
}

template <class TClientType>
bool EndPoint::Impl<TClientType>::updateState()
{
    websocketpp::lib::error_code ec; // for supression of exception
    if (const auto conn = _client.get_con_from_hdl(hdl(), ec)) {
        return setState(conn->get_state());
    }
    return setState(Websocket::State::Disconnected);
}

template <class TClientType>
void EndPoint::Impl<TClientType>::setHdl(const Hdl& hdl)
{
    LOCK_WRITE_PROTECTED_OBJ(_hdl);
    _hdl = hdl;
}

template <class TClientType>
Hdl EndPoint::Impl<TClientType>::hdl() const
{
    LOCK_READ_PROTECTED_OBJ(_hdl);
    return _hdl.constRef();
}

template <class TClientType>
void EndPoint::Impl<TClientType>::onInit(const Hdl& hdl)
{
    setHdl(hdl);
    updateState();
}

template <class TClientType>
void EndPoint::Impl<TClientType>::onFail(const Hdl& hdl)
{
    websocketpp::lib::error_code ec;
    if (const auto connection = _client.get_con_from_hdl(hdl, ec)) {
        ec = connection->get_ec();
    }
    if (ec) {
        // report error
        notifyAboutError(Websocket::Failure::General, ec);
    }
    updateState();
}

template <class TClientType>
void EndPoint::Impl<TClientType>::onOpen(const Hdl& hdl)
{
    maybeSetOption<asio::socket_base::broadcast>(options()._broadcast, hdl);
    maybeSetOption<asio::socket_base::do_not_route>(options()._doNotRoute, hdl);
    maybeSetOption<asio::socket_base::keep_alive>(options()._keepAlive, hdl);
    maybeSetOption<asio::socket_base::linger>(options()._linger, hdl);
    maybeSetOption<asio::socket_base::receive_buffer_size>(options()._receiveBufferSize, hdl);
    maybeSetOption<asio::socket_base::receive_low_watermark>(options()._receiveLowWatermark, hdl);
    maybeSetOption<asio::socket_base::reuse_address>(options()._reuseAddress, hdl);
    maybeSetOption<asio::socket_base::send_buffer_size>(options()._sendBufferSize, hdl);
    maybeSetOption<asio::socket_base::send_low_watermark>(options()._sendLowWatermark, hdl);
    maybeSetOption<asio::ip::tcp::no_delay>(options()._tcpNoDelay, hdl);
    updateState();
}

template <class TClientType>
void EndPoint::Impl<TClientType>::onMessage(const Hdl& hdl, MessagePtr message)
{
    if (message) {
        switch (message->get_opcode()) {
            case _text:
                _listener->onTextMessage(socketId(), connectionId(), toText(std::move(message)));
                break;
            case _binary:
                _listener->onBinaryMessage(socketId(), connectionId(),
                                           std::make_shared<MessageBlobImpl>(std::move(message)));
                break;
            default:
                break;
        }
    }
}

template <class TClientType>
void EndPoint::Impl<TClientType>::onClose(const Hdl&)
{
    if (_destroyed) {
        delete this;
    }
    else {
        updateState();
        setHdl({});
    }
}

EndPoint::TlsOn::TlsOn(uint64_t id, uint64_t connectionId, Config config,
                       const std::shared_ptr<Websocket::Listener>& listener,
                       const std::shared_ptr<ServiceProvider>& serviceProvider,
                       const std::shared_ptr<Logger>& logger) noexcept(false)
    : Impl<asio_tls_client>(id, connectionId, std::move(config), listener, serviceProvider, logger)
{
    client().set_tls_init_handler(bind(&TlsOn::onInitTls, this, _1));
}

EndPoint::TlsOn::~TlsOn()
{
    client().set_tls_init_handler(nullptr);
}

std::shared_ptr<SSLCtx> EndPoint::TlsOn::onInitTls(const Hdl&)
{
    try {
        return serviceProvider()->createSslContext(options()._tls);
    } catch (const std::system_error& e) {
        notifyAboutError(Websocket::Failure::TlsOptions, e);
    }
    return nullptr;
}

EndPoint::TlsOff::TlsOff(uint64_t id, uint64_t connectionId, Config config,
                         const std::shared_ptr<Websocket::Listener>& listener,
                         const std::shared_ptr<ServiceProvider>& serviceProvider,
                         const std::shared_ptr<Logger>& logger) noexcept(false)
    : Impl<asio_client>(id, connectionId, std::move(config), listener, serviceProvider, logger)
{
}

void EndPoint::Listener::onStateChanged(uint64_t socketId, uint64_t connectionId,
                                        Websocket::State state)
{
    Websocket::Listener::onStateChanged(socketId, connectionId, state);
    _listeners.invokeMethod(&Websocket::Listener::onStateChanged, socketId,
                            connectionId, state);
}

void EndPoint::Listener::onError(uint64_t socketId, uint64_t connectionId,
                                 const Websocket::Error& error)
{
    Websocket::Listener::onError(socketId, connectionId, error);
    _listeners.invokeMethod(&Websocket::Listener::onError, socketId,
                            connectionId, error);
}

void EndPoint::Listener::onTextMessage(uint64_t socketId, uint64_t connectionId,
                                       const std::string_view& message)
{
    Websocket::Listener::onTextMessage(socketId, connectionId, message);
    _listeners.invokeMethod(&Websocket::Listener::onTextMessage,
                            socketId, connectionId, message);
}

void EndPoint::Listener::onBinaryMessage(uint64_t socketId, uint64_t connectionId,
                                         const std::shared_ptr<Blob>& message)
{
    Websocket::Listener::onBinaryMessage(socketId, connectionId, message);
    _listeners.invokeMethod(&Websocket::Listener::onBinaryMessage,
                            socketId, connectionId, message);
}

} // namespace Tpp

namespace {

LogStream::LogStream(LoggingSeverity severity, const std::shared_ptr<Logger>& logger)
    : LoggableS<std::streambuf>(logger)
    , _severity(severity)
    , _output(this)
{
}

std::streamsize LogStream::xsputn(const char* s, std::streamsize count)
{
    if (s && count && canLog(_severity)) {
        std::string_view data(s, count);
        if (data.front() == '\n') {
            data = data.substr(1U, data.size() - 1U);
        }
        if (!data.empty() && data.back() == '\n') {
            data = data.substr(0U, data.size() - 1U);
        }
        if (!data.empty()) {
            LOCK_WRITE_PROTECTED_OBJ(_logBuffer);
            _logBuffer->append(data.data(), data.size());
        }
    }
    return count;
}

int LogStream::sync()
{
    sendBufferToLog();
    return 0;
}

LogStream::~LogStream()
{
    if (pbase() != pptr()) {
        sendBufferToLog();
    }
}

void LogStream::sendBufferToLog()
{
    LOCK_WRITE_PROTECTED_OBJ(_logBuffer);
    if (!_logBuffer->empty()) {
        log(_severity, _logBuffer.constRef(), g_logCategory);
        _logBuffer->clear();
    }
}

}
