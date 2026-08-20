#pragma once // TestBlob.h
#include "Blob.h"
#include <string>
#include <utility>

namespace Tests
{

// Minimal Bricks::Blob implementation for feeding payloads into
// Websocket::EndPoint::sendBinary()/ping() from tests.
class TestBlob : public Bricks::Blob
{
public:
    explicit TestBlob(std::string payload) : _payload(std::move(payload)) {}
    // impl. of Bricks::Blob
    size_t size() const override { return _payload.size(); }
    const uint8_t* data() const override {
        return reinterpret_cast<const uint8_t*>(_payload.data());
    }
private:
    const std::string _payload;
};

} // namespace Tests
