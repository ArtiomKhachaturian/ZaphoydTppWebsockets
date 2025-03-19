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
#pragma once // ServiceProvider.h
#include "TypeDefs.h"

namespace Websocket {
struct Tls;
}

namespace Tpp
{

/**
 * @brief Abstract base class for managing service I/O operations and SSL contexts.
 *
 * The `ServiceProvider` class defines an interface for starting and stopping I/O services,
 * retrieving service instances, and creating SSL contexts based on TLS configurations.
 * Derived classes must implement these methods to provide specific functionality.
 */
class ServiceProvider
{
public:
    /**
     * @brief Virtual destructor for proper cleanup of derived classes.
     */
    virtual ~ServiceProvider() = default;

    /**
     * @brief Starts the service.
     *
     * This method initializes and begins the operation of the I/O service. Derived classes
     * must provide the implementation to define how the service is started.
     */
    virtual void startService() = 0;

    /**
     * @brief Stops the service.
     *
     * This method terminates the operation of the I/O service, ensuring proper cleanup and
     * resource release. Derived classes must define how the service is stopped.
     */
    virtual void stopService() = 0;

    /**
     * @brief Retrieves the service instance.
     *
     * This method provides access to the current service instance, allowing interaction
     * with the service. Derived classes must return the specific service implementation.
     *
     * @return A pointer to the service instance (`IOSrv`).
     */
    virtual IOSrv* service() = 0;

    /**
     * @brief Creates an SSL context based on the provided TLS configuration.
     *
     * This method initializes and returns an SSL context using the settings specified
     * in the `Websocket::Tls` configuration. Derived classes must implement the creation
     * logic.
     *
     * @param tls The TLS configuration containing protocol, certificate, and other options.
     * @return A shared pointer to the created `SSLCtx` instance.
     */
    virtual std::shared_ptr<SSLCtx> createSslContext(const Websocket::Tls& tls) const = 0;
};


} // namespace Tpp
