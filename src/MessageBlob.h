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
#pragma once // MessageBlob.h
#include "Blob.h"

namespace Tpp
{

template<class MessagePtr>
class MessageBlob : public Bricks::Blob
{
public:
    MessageBlob(const MessagePtr& message);
    // impl. of Bricks::Blob
    size_t size() const final;
    const uint8_t* data() const final;
private:
    const MessagePtr _message;
};

template<class MessagePtr>
inline MessageBlob<MessagePtr>::MessageBlob(const MessagePtr& message)
    : _message(message)
{
}

template<class MessagePtr>
inline size_t MessageBlob<MessagePtr>::size() const
{
    if (_message) {
        return _message->get_raw_payload().size();
    }
    return 0U;
}

template<class MessagePtr>
inline const uint8_t* MessageBlob<MessagePtr>::data() const
{
    if (_message) {
        const auto& payload = _message->get_raw_payload();
        return reinterpret_cast<const uint8_t*>(payload.data());
    }
    return nullptr;
}

} // namespace Tpp
