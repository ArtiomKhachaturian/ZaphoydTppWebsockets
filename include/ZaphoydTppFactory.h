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

/**
 * @brief A factory class for creating WebSocket endpoints with integration to TPP services.
 *
 * The `ZaphoydTppFactory` class provides a specialized implementation of the `Websocket::Factory`
 * interface. It integrates with the `Bricks::Logger` for logging and the `Tpp::ServiceProvider`
 * for service provisioning.
 */
class ZAPHOYD_TPP_API ZaphoydTppFactory : public Websocket::Factory
{
    /**
     * @brief Internal implementation class for handling service provisioning.
     */
    class ServiceImpl;

public:
    /**
     * @brief Constructs a class  instance.
     *
     * @param logger A shared pointer to a `Bricks::Logger` instance for logging activities.
     *               If not provided, logging is disabled.
     */
    ZaphoydTppFactory(const std::shared_ptr<Bricks::Logger>& logger = {});

    /**
     * @brief Destructor for cleaning up the factory.
     */
    ~ZaphoydTppFactory() final;

    /**
     * @brief Creates a new websocket endpoint.
     *
     * This method provides a concrete implementation of the `create` method from the
     * `Websocket::Factory` interface.
     *
     * @return A `std::unique_ptr` to a newly created `Websocket::EndPoint` instance.
     */
    std::unique_ptr<Websocket::EndPoint> create() const final;

private:
    /**
     * @brief Retrieves the TPP service provider.
     *
     * This method provides access to the `Tpp::ServiceProvider` associated with the factory.
     *
     * @return A shared pointer to the `Tpp::ServiceProvider` instance.
     */
    std::shared_ptr<Tpp::ServiceProvider> serviceProvider() const;

private:
    /// @brief Logger instance used for logging WebSocket events and activities.
    const std::shared_ptr<Bricks::Logger> _logger;

    /// @brief Service implementation for managing TPP service integrations.
    const std::shared_ptr<ServiceImpl> _serviceProvider;
};
