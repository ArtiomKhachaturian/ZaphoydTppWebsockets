#pragma once // RecordingListener.h
#include "WebsocketListener.h"
#include "WebsocketState.h"
#include "WebsocketError.h"
#include "Blob.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace Tests
{

// Websocket::Listener test double: records every callback into vectors guarded
// by a mutex + condition variable, since callbacks arrive asynchronously on the
// library's background io_service thread, not the test thread.
class RecordingListener : public Websocket::Listener
{
public:
    // impl. of Websocket::Listener
    void onStateChanged(uint64_t /*socketId*/, uint64_t /*connectionId*/,
                        Websocket::State state) override {
        std::lock_guard<std::mutex> lock(_mutex);
        _states.push_back(state);
        _cv.notify_all();
    }

    void onError(uint64_t /*socketId*/, uint64_t /*connectionId*/,
                const Websocket::Error& error) override {
        std::lock_guard<std::mutex> lock(_mutex);
        _errors.push_back(error);
        _cv.notify_all();
    }

    void onTextMessage(uint64_t /*socketId*/, uint64_t /*connectionId*/,
                       const std::string_view& message) override {
        std::lock_guard<std::mutex> lock(_mutex);
        _textMessages.emplace_back(message);
        _cv.notify_all();
    }

    void onBinaryMessage(uint64_t /*socketId*/, uint64_t /*connectionId*/,
                         const Bricks::Blob& message) override {
        std::lock_guard<std::mutex> lock(_mutex);
        _binaryMessages.emplace_back(reinterpret_cast<const char*>(message.data()),
                                     message.size());
        _cv.notify_all();
    }

    void onPong(uint64_t /*socketId*/, uint64_t /*connectionId*/,
               const Bricks::Blob& /*payload*/) override {
        std::lock_guard<std::mutex> lock(_mutex);
        ++_pongCount;
        _cv.notify_all();
    }

    // Waiters: block until the predicate over the current snapshot holds, or
    // timeout elapses. Return false on timeout.
    bool waitForState(Websocket::State state,
                      std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        std::unique_lock<std::mutex> lock(_mutex);
        return _cv.wait_for(lock, timeout, [&] {
            return !_states.empty() && state == _states.back();
        });
    }

    bool waitForTextMessages(size_t count,
                             std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        std::unique_lock<std::mutex> lock(_mutex);
        return _cv.wait_for(lock, timeout, [&] { return _textMessages.size() >= count; });
    }

    bool waitForBinaryMessages(size_t count,
                               std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        std::unique_lock<std::mutex> lock(_mutex);
        return _cv.wait_for(lock, timeout, [&] { return _binaryMessages.size() >= count; });
    }

    bool waitForPongs(size_t count,
                      std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        std::unique_lock<std::mutex> lock(_mutex);
        return _cv.wait_for(lock, timeout, [&] { return _pongCount >= count; });
    }

    bool waitForErrors(size_t count,
                       std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        std::unique_lock<std::mutex> lock(_mutex);
        return _cv.wait_for(lock, timeout, [&] { return _errors.size() >= count; });
    }

    // Snapshot accessors, safe to call after a successful wait above.
    std::vector<std::string> textMessages() const {
        std::lock_guard<std::mutex> lock(_mutex);
        return _textMessages;
    }

    std::vector<std::string> binaryMessages() const {
        std::lock_guard<std::mutex> lock(_mutex);
        return _binaryMessages;
    }

    size_t pongCount() const {
        std::lock_guard<std::mutex> lock(_mutex);
        return _pongCount;
    }

    size_t errorCount() const {
        std::lock_guard<std::mutex> lock(_mutex);
        return _errors.size();
    }

private:
    mutable std::mutex _mutex;
    std::condition_variable _cv;
    std::vector<Websocket::State> _states;
    std::vector<Websocket::Error> _errors;
    std::vector<std::string> _textMessages;
    std::vector<std::string> _binaryMessages;
    size_t _pongCount = 0U;
};

} // namespace Tests
