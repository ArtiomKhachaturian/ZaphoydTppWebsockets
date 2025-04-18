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
#pragma once // EndPoint.h
#include "Loggable.h"
#include "WebsocketEndPoint.h"
#include "SafeObjAliases.h"

namespace Bricks {
class Logger;
}

namespace Tpp
{

class ServiceProvider;
class Api;

class EndPoint : public Bricks::LoggableS<Websocket::EndPoint>
{
    template<class TClientType> class Impl;
    class TlsOn;
    class TlsOff;
public:
    EndPoint(const std::shared_ptr<ServiceProvider>& serviceProvider,
             const std::shared_ptr<Bricks::Logger>& logger = {});
    ~EndPoint() final;
    // impl. of Websocket
    void setListener(const std::shared_ptr<Websocket::Listener>& listener) final;
    bool open(Websocket::Options options, uint64_t connectionId) final;
    void close() final;
    std::string host() const final;
    Websocket::State state() const final;
    bool sendBinary(const Bricks::Blob& binary) final;
    bool sendText(std::string_view text) final;
    bool ping(const Bricks::Blob& payload) final;
    bool ping() final;
private:
    // increase read buffer size to optimize for huge audio/video messages:
    // 64 Kb instead of 16 by default, see details at
    // https://docs.websocketpp.org/structwebsocketpp_1_1config_1_1core.html#af1f28eec2b5e12b6d7cccb0c87835119
    static inline constexpr size_t _readBufferSize = 65536U;
    const std::shared_ptr<Api> _tlsOn;
    const std::shared_ptr<Api> _tlsOff;
    std::shared_ptr<Websocket::Listener> _listener;
    std::shared_ptr<Api> _active;
};

} // namespace Tpp
