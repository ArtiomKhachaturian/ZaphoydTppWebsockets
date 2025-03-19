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

// other static attributes are possible
// from https://docs.websocketpp.org/structwebsocketpp_1_1config_1_1core.html
/**
 * @brief Template for extending WebSocket++ configuration.
 *
 * The `Extension` struct acts as a base class to extend configurations
 * defined in `WebSocket++`. It inherits from the provided configuration type.
 *
 * @tparam TConfig The WebSocket++ configuration type to extend.
 */
template <class TConfig>
struct Extension : public TConfig {};

/**
 * @brief Template for extending the read buffer size in WebSocket++ connections.
 *
 * This template allows customization of the read buffer size for WebSocket++ connections.
 *
 * @tparam ReadBufferSize The size of the read buffer (must be greater than 0).
 * @tparam TConfig The WebSocket++ configuration type to extend.
 */
template <size_t ReadBufferSize, class TConfig>
struct ReadBufferExtension : public Extension<TConfig>
{
    static_assert(ReadBufferSize > 0U, "ReadBufferSize must be greater than 0");

    /**
     * @brief Specifies the connection's read buffer size.
     */
    static const size_t connection_read_buffer_size = ReadBufferSize;
};

/**
 * @brief Specialized template for zero-sized read buffer extensions.
 *
 * Provides a default implementation when `ReadBufferSize` is 0.
 *
 * @tparam TConfig The WebSocket++ configuration type to extend.
 */
template <class TConfig>
struct ReadBufferExtension<0U, TConfig> : public Extension<TConfig> {};

/**
 * @brief Template for converting values to specific socket options.
 *
 * The `ValueToOption` struct provides a utility for converting generic values
 * into socket options used by WebSocket++.
 *
 * @tparam TOption The socket option type to convert to.
 * @tparam T The type of the input value to be converted.
 */
template <class TOption, typename T>
struct ValueToOption
{
    /**
     * @brief Converts a value to the specified socket option type.
     *
     * @param value The input value to convert.
     * @return The converted socket option.
     */
    static TOption convert(const T& value) { return TOption(value); }
};

/**
 * @brief Specialization for converting `Websocket::Options::Linger` to `socket_base::linger`.
 *
 * This specialization handles the conversion of linger options used in WebSocket++ connections.
 */
template <>
struct ValueToOption<websocketpp::lib::asio::socket_base::linger, Websocket::Options::Linger>
{
    /**
     * @brief Converts a `Linger` value to `socket_base::linger`.
     *
     * @param linger The input linger configuration.
     * @return The converted `socket_base::linger` object.
     */
    static auto convert(const Websocket::Options::Linger& linger) {
        return websocketpp::lib::asio::socket_base::linger(linger.first, linger.second);
    }
};

} // namespace Tpp
