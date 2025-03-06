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
#pragma once // Config.h
#include "WebsocketOptions.h"
#include <websocketpp/uri.hpp>

namespace Tpp
{

class Config
{
public:
    static Config create(Websocket::Options options);
    Config() = default;
    Config(const Config&) = default;
    Config(Config&&) = default;
    const websocketpp::uri_ptr& uri() const noexcept { return _uri; }
    const Websocket::Options& options() const noexcept { return _options; }
    bool valid() const noexcept { return nullptr != uri(); }
    bool secure() const noexcept;
    Config& operator = (const Config&) = default;
    Config& operator = (Config&&) = default;
    explicit operator bool () const noexcept { return valid(); }
    operator const Websocket::Options& () const noexcept { return options(); }
    operator const websocketpp::uri_ptr& () const noexcept { return uri(); }
private:
    Config(websocketpp::uri_ptr uri, Websocket::Options options);
private:
    websocketpp::uri_ptr _uri;
    Websocket::Options _options;
};

} // namespace Tpp
