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
#pragma once // Extensions.h
#include "WebsocketOptions.h"
#include <websocketpp/common/asio.hpp> // for asio::socket_base::linger

namespace Tpp
{

// maybe other static attributes
// from https://docs.websocketpp.org/structwebsocketpp_1_1config_1_1core.html
template <class TConfig>
struct Extension : public TConfig {};

template <size_t ReadBufferSize, class TConfig>
struct ReadBufferExtension : public Extension<TConfig>
{
    static_assert(ReadBufferSize > 0U);
    static const size_t connection_read_buffer_size = ReadBufferSize;
};

template <class TConfig>
struct ReadBufferExtension<0U, TConfig> : public Extension<TConfig> {};

template <class TOption, typename T>
struct ValueToOption
{
    static TOption convert(const T& value) { return TOption(value); }
};

template <>
struct ValueToOption<websocketpp::lib::asio::socket_base::linger, Websocket::Options::Linger>
{
    static auto convert(const Websocket::Options::Linger& linger) {
        return websocketpp::lib::asio::socket_base::linger(linger.first, linger.second);
    }
};

} // namespace Tpp
