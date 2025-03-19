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
#pragma once // ThreadPriority.h
#ifdef _WIN32
#include <Windows.h>
#endif

namespace Tpp
{

enum class ThreadPriority : int
{
#ifdef _WIN32
    Auto     = THREAD_BASE_PRIORITY_MIN,
    Low      = THREAD_PRIORITY_BELOW_NORMAL,
    Normal   = THREAD_PRIORITY_NORMAL,
    High     = THREAD_PRIORITY_ABOVE_NORMAL,
    Highest  = THREAD_PRIORITY_HIGHEST,
    Realtime = THREAD_PRIORITY_TIME_CRITICAL
#else
    /**
     * @brief Automatically determine the thread priority.
     */
    Auto = 0,

    /**
     * @brief Low thread priority.
     */
    Low = 1,

    /**
     * @brief Normal thread priority.
     */
    Normal = 2,

    /**
     * @brief High thread priority.
     */
    High = 3,

    /**
     * @brief Highest thread priority.
     */
    Highest = 4,

    /**
     * @brief Real-time thread priority.
     */
    Realtime = 5
#endif
};

/**
 * @brief Converts a `ThreadPriority` value to its string representation.
 *
 * This function provides a human-readable string for each thread priority level.
 * It aids in debugging and logging operations related to thread management.
 *
 * @param priority The `ThreadPriority` enum value to convert.
 * @return A constant character pointer representing the string equivalent of the priority level.
 */
const char* ToString(ThreadPriority priority);

} // namespace Tpp
