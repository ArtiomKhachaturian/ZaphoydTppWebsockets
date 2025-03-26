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
#include "ZaphoydTppFactory.h"
#include "EndPoint.h"
#include "ServiceProvider.h"
#include "WebsocketTls.h"
#include "ThreadExecution.h"
#include <optional>

using namespace Tpp;

namespace {

inline auto makeBuffer(const std::string& buffer) {
    return websocketpp::lib::asio::const_buffer(buffer.data(), buffer.size());
}

inline auto format(bool pem) {\
    if (pem) {
        return SSLCtx::file_format::pem;
    }
    return SSLCtx::file_format::asn1;
}

}

class ZaphoydTppFactory::ServiceImpl : public ServiceProvider,
                                       private ThreadExecution
{
public:
    ServiceImpl(const std::shared_ptr<Bricks::Logger>& logger = {});
    ~ServiceImpl() final { stopExecution(); }
    // impl. of WebsocketTppServiceProvider
    void startService() final { startExecution(); }
    void stopService() final { stopExecution(); }
    IOSrv* service() final { return _service.get(); }
    std::shared_ptr<SSLCtx> createSslContext(const Websocket::Tls& tls) const final;
protected:
    // impl. of ThreadExecution
    void doExecuteInThread() final;
    void doStopThread() final;
private:
    static std::optional<SSLCtx::method> convert(Websocket::TlsMethod method);
    static const auto& sslErrorCategory() { return websocketpp::lib::asio::error::get_ssl_category(); }
private:
    const std::shared_ptr<IOSrv> _service;
};

ZaphoydTppFactory::ZaphoydTppFactory(const std::shared_ptr<Bricks::Logger>& logger)
    : _logger(logger)
{
}

ZaphoydTppFactory::~ZaphoydTppFactory()
{
}

std::shared_ptr<ServiceProvider> ZaphoydTppFactory::serviceProvider() const
{
    return std::make_shared<ServiceImpl>(_logger);
}

std::unique_ptr<Websocket::EndPoint> ZaphoydTppFactory::create() const
{
    return std::make_unique<Tpp::EndPoint>(serviceProvider(), _logger);
}

ZaphoydTppFactory::ServiceImpl::ServiceImpl(const std::shared_ptr<Bricks::Logger>& logger)
    : ThreadExecution("WebsocketsTPP", ThreadPriority::Highest, logger)
    , _service(std::make_shared<IOSrv>())
{
}

std::shared_ptr<SSLCtx> ZaphoydTppFactory::ServiceImpl::
    createSslContext(const Websocket::Tls& tls) const
{
    if (const auto method = convert(tls._method)) {
        try {
            auto ctx = std::make_shared<SSLCtx>(method.value());
            bool verify = false;
            if (!tls._trustStore.empty()) {
                ctx->add_certificate_authority(makeBuffer(tls._trustStore));
                verify = true;
            }
            if (!tls._certificate.empty()) {
                ctx->use_certificate_chain(makeBuffer(tls._certificate));
                ctx->use_private_key(makeBuffer(tls._certificatePrivateKey),
                                     format(tls._certificateIsPem));
                auto callback = [password = tls._certificatePrivateKeyPassword](
                    std::size_t /*size*/, SSLCtx::password_purpose /*purpose*/) {
                        return password;
                };
                ctx->set_password_callback(std::move(callback));
                verify = true;
            }
            if (!tls._sslCiphers.empty()) {
                const auto res = SSL_CTX_set_cipher_list(ctx->native_handle(), tls._sslCiphers.c_str());
                if (0 == res) { // https://www.openssl.org/docs/man3.1/man3/SSL_CTX_set_cipher_list.html
                    // return 1 if any cipher could be selected and 0 on complete failure
                    const auto error = static_cast<int>(ERR_get_error());
                    throw std::system_error(error, sslErrorCategory(), "SSL_CTX_set_cipher_list");
                }
            }
            if (!tls._dh.empty()) {
                const auto& dh = tls._dh;
                ctx->use_tmp_dh(makeBuffer(dh));
            }
            if (verify) {
                const auto& verification = tls._peerVerification;
                if (Websocket::TlsPeerVerification::No != verification) {
                    SSLCtx::verify_mode mode = SSLCtx::verify_peer;
                    if (Websocket::TlsPeerVerification::YesAndRejectIfNoCert == verification) {
                        mode |= SSLCtx::verify_fail_if_no_peer_cert;
                    }
                    ctx->set_verify_mode(mode);
                }
            }
            SSLCtx::options options = SSLCtx::default_workarounds;
            if (tls._dhSingle) {
                options |= SSLCtx::single_dh_use;
            }
            if (tls._sslv2No) {
                options |= SSLCtx::no_sslv2;
            }
            if (tls._sslv3No) {
                options |= SSLCtx::no_sslv3;
            }
            if (tls._tlsv1No) {
                options |= SSLCtx::no_tlsv1;
            }
            if (tls._tlsv1_1No) {
                options |= SSLCtx::no_tlsv1_1;
            }
            if (tls._tlsv1_2No) {
                options |= SSLCtx::no_tlsv1_2;
            }
            if (tls._tlsv1_3No) {
                options |= SSLCtx::no_tlsv1_3;
            }
            if (tls._sslNoCompression) {
                options |= SSLCtx::no_compression;
            }
            ctx->set_options(options);
            return ctx;
        }
        catch (const SysError& e) {
            const auto& code = e.code();
            throw std::system_error(code.value(), code.category());
        }
    }
    return nullptr;
}

void ZaphoydTppFactory::ServiceImpl::doExecuteInThread()
{
    // local copy for keep lifetime if thread was detached
    const auto service(_service);
    websocketpp::lib::asio::error_code ec;
    service->run(ec);
    if (ec) {
        logError(ec.message());
    }
}

void ZaphoydTppFactory::ServiceImpl::doStopThread()
{
    _service->stop();
}

std::optional<SSLCtx::method> ZaphoydTppFactory::ServiceImpl::
    convert(Websocket::TlsMethod method)
{
    switch (method) {
        case Websocket::TlsMethod::sslv2:
            return SSLCtx::method::sslv2;
        case Websocket::TlsMethod::sslv2_client:
            return SSLCtx::method::sslv2_client;
        case Websocket::TlsMethod::sslv2_server:
            return SSLCtx::method::sslv2_server;
        case Websocket::TlsMethod::sslv3:
            return SSLCtx::method::sslv3;
        case Websocket::TlsMethod::sslv3_client:
            return SSLCtx::method::sslv3_client;
        case Websocket::TlsMethod::sslv3_server:
            return SSLCtx::method::sslv3_server;
        case Websocket::TlsMethod::tlsv1:
            return SSLCtx::method::tlsv1;
        case Websocket::TlsMethod::tlsv1_client:
            return SSLCtx::method::tlsv1_client;
        case Websocket::TlsMethod::tlsv1_server:
            return SSLCtx::method::tlsv1_server;
        case Websocket::TlsMethod::sslv23:
            return SSLCtx::method::sslv23;
        case Websocket::TlsMethod::sslv23_client:
            return SSLCtx::method::sslv23_client;
        case Websocket::TlsMethod::sslv23_server:
            return SSLCtx::method::sslv23_server;
        case Websocket::TlsMethod::tlsv11:
            return SSLCtx::method::tlsv11;
        case Websocket::TlsMethod::tlsv11_client:
            return SSLCtx::method::tlsv11_client;
        case Websocket::TlsMethod::tlsv11_server:
            return SSLCtx::method::tlsv11_server;
        case Websocket::TlsMethod::tlsv12:
            return SSLCtx::method::tlsv12;
        case Websocket::TlsMethod::tlsv12_client:
            return SSLCtx::method::tlsv12_client;
        case Websocket::TlsMethod::tlsv12_server:
            return SSLCtx::method::tlsv12_server;
        case Websocket::TlsMethod::tlsv13:
            return SSLCtx::method::tlsv13;
        case Websocket::TlsMethod::tlsv13_client:
            return SSLCtx::method::tlsv13_client;
        case Websocket::TlsMethod::tlsv13_server:
            return SSLCtx::method::tlsv13_server;
        case Websocket::TlsMethod::tls:
            return SSLCtx::method::tls;
        case Websocket::TlsMethod::tls_client:
            return SSLCtx::method::tls_client;
        case Websocket::TlsMethod::tls_server:
            return SSLCtx::method::tls_server;
        default:
            break;
    }
    return std::nullopt;
}
