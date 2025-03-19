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
#pragma once // ThreadExecution.h
#include "Loggable.h"
#include "ThreadPriority.h"
#include "SafeObj.h"
#include <atomic>
#include <string>
#include <system_error>
#include <thread>

namespace Tpp
{

/**
 * @brief Class for managing thread execution with configurable priority and logging.
 *
 * The `ThreadExecution` class provides functionality for executing tasks in a thread
 * with priority settings and thread naming.
 */
class ThreadExecution : public Bricks::LoggableS<>
{
public:
    /**
     * @brief Virtual destructor for proper cleanup of derived classes.
     */
    virtual ~ThreadExecution();

    /**
     * @brief Retrieves the name of the thread.
     *
     * @return A constant reference to the thread name string.
     */
    const std::string& GetThreadName() const noexcept { return _threadName; }

    /**
     * @brief Retrieves the thread's priority.
     *
     * @return The priority level of the thread as a `ThreadPriority` enum value.
     */
    ThreadPriority GetPriority() const noexcept { return _priority; }

    /**
     * @brief Starts the execution of the thread.
     *
     * This method initializes the thread routine. If `waitingUntilNotStarted` is true,
     * it will wait until the thread is not already started.
     *
     * @param waitingUntilNotStarted If true, waits until the thread is not already started.
     */
    void startExecution(bool waitingUntilNotStarted = false);

    /**
     * @brief Stops the thread execution.
     *
     * This method must be called before destroying an instance of a derived class.
     */
    void stopExecution();

    /**
     * @brief Checks if the thread is started.
     *
     * @return `true` if the thread has been initialized, otherwise `false`.
     */
    bool started() const noexcept;

    /**
     * @brief Checks if the thread is active.
     *
     * A thread may be started but not yet active until fully initialized.
     *
     * @return `true` if the thread is active, otherwise `false`.
     */
    bool active() const noexcept;

protected:
    /**
     * @brief Constructor for initializing a `ThreadExecution` instance.
     *
     * @param threadName The name of the thread (default: empty string).
     * @param priority The priority level for the thread (default: `ThreadPriority::High`).
     * @param logger A shared pointer to the logger instance (default: `nullptr`).
     */
    ThreadExecution(std::string threadName = std::string(),
                    ThreadPriority priority = ThreadPriority::High,
                    const std::shared_ptr<Bricks::Logger>& logger = {});

    /**
     * @brief The routine executed inside the thread.
     *
     * Derived classes must implement this method to provide custom functionality
     * for execution in the thread.
     */
    virtual void doExecuteInThread() = 0;

    /**
     * @brief Called when the internal state changes to 'stopped'.
     *
     * This method is invoked before the thread execution is joined, allowing
     * for cleanup operations.
     */
    virtual void doStopThread() {}

    /**
     * @brief Called when setting the thread priority fails.
     *
     * This method is invoked in case of non-critical issues with setting the
     * thread's priority. It can be overridden for custom error handling.
     *
     * @param error The error code describing the failure.
     */
    virtual void onSetThreadPriorityError(const std::error_code& error);

    /**
     * @brief Called when setting the thread name fails.
     *
     * This method is invoked for non-critical errors related to thread naming.
     * It can be ignored or overridden for custom handling.
     *
     * @param error The error code describing the failure (default implementation: ignored).
     */
    virtual void onSetThreadNameError(const std::error_code& /*error*/) {}

private:
    /**
     * @brief Deleted copy constructor to prevent copying of instances.
     */
    ThreadExecution(const ThreadExecution&) = delete;

    /**
     * @brief Deleted move constructor to prevent moving of instances.
     */
    ThreadExecution(ThreadExecution&&) = delete;

    /**
     * @brief Joins and destroys the thread.
     *
     * Ensures proper cleanup of thread resources during destruction.
     */
    void joinAndDestroyThread();

    /**
     * @brief Executes the thread routine.
     *
     * Internally invokes the thread execution logic.
     */
    void execute();

    /**
     * @brief Sets the name for the current thread.
     *
     * @return An error code indicating the success or failure of the operation.
     */
    std::error_code SetCurrentThreadName() const;

    /**
     * @brief Sets the priority for the current thread.
     *
     * @return An error code indicating the success or failure of the operation.
     */
    std::error_code SetCurrentThreadPriority() const;

private:
    /// @brief The name of the thread.
    const std::string _threadName;

    /// @brief The priority level of the thread.
    const ThreadPriority _priority;

    /// @brief thread object.
    Bricks::SafeObj<std::thread, std::mutex> _thread;

    /// @brief Indicates if the thread has been started.
    bool _started = false;
};

} // namespace Tpp
