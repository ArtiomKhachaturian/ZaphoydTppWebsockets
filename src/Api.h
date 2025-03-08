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
#pragma once // Api.h
#include <string_view>

namespace Bricks {
class Blob;
}

namespace Websocket {
enum class State;
}

namespace Tpp
{

class Api
{
public:
    virtual ~Api() = default;
    virtual bool open() = 0;
    virtual std::string host() const = 0;
    virtual Websocket::State state() const = 0;
    virtual void destroy() = 0;
    virtual bool sendBinary(const Bricks::Blob& binary) = 0;
    virtual bool sendText(std::string_view text) = 0;
    virtual bool ping(const Bricks::Blob& payload) = 0;
};

} // namespace Tpp
