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
#pragma once // ZaphoydTppFactory.h
#include "WebsocketFactory.h"
#include "ZaphoydTppExport.h"

// prototype defined in 'Bricks' library,
// see https://github.com/ArtiomKhachaturian/Bricks
namespace Bricks {
class Logger;
}

namespace Tpp {
class ServiceProvider;
}

class ZAPHOYD_TPP_API ZaphoydTppFactory : public Websocket::Factory
{
    class ServiceImpl;
public:
    ZaphoydTppFactory(const std::shared_ptr<Bricks::Logger>& logger = {});
    // impl. of Factory
    ~ZaphoydTppFactory() final;
    std::unique_ptr<Websocket::EndPoint> create() const final;
private:
    std::shared_ptr<Tpp::ServiceProvider> serviceProvider() const;
private:
    const std::shared_ptr<Bricks::Logger> _logger;
    const std::shared_ptr<ServiceImpl> _serviceProvider;
};
