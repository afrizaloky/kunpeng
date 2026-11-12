#include "host_call_dispatcher.h"
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace kunpeng {
void HostCallDispatcher::registerHandler(std::uint32_t operation, HostCallHandler handler)
{
    if (!operation || !handler || handlers_.count(operation))
        throw std::invalid_argument("host call: invalid or duplicate registration");
    handlers_.emplace(operation, std::move(handler));
}
HostCallReply HostCallDispatcher::dispatch(const HostCallRequest& request) const
{
    if (!request.operation || !request.id || request.arguments.size() > HOST_CALL_PAYLOAD_CAP)
        throw std::invalid_argument("host call: invalid request");
    const auto handler = handlers_.find(request.operation);
    if (handler == handlers_.end()) return {HostCallStatus::Error, {}};
    auto reply = handler->second(request);
    if (reply.data.size() > HOST_CALL_OBJECT_CAP)
        throw std::length_error("host call: reply exceeds object capacity");
    return reply;
}
std::vector<unsigned char> HostCallDispatcher::encodeChunk(const HostCallRequest& request,
    const HostCallReply& reply, std::size_t offset)
{
    if (reply.data.size() > HOST_CALL_OBJECT_CAP || offset > reply.data.size())
        throw std::length_error("host call: invalid reply offset or size");
    const bool error = reply.status == HostCallStatus::Error;
    if (error && offset != 0) throw std::invalid_argument("host call: error offset");
    const auto length = error ? 0 : std::min<std::size_t>(HOST_CALL_PAYLOAD_CAP, reply.data.size() - offset);
    const bool final = error || offset + length == reply.data.size();
    std::vector<unsigned char> wire(HOST_CALL_HEADER_SIZE + length);
    host_call_chunk metadata{request.operation, request.id,
        static_cast<std::uint32_t>(offset), static_cast<std::uint32_t>(length),
        error ? HOST_CALL_HOST_ERROR : HOST_CALL_OK, final ? 1u : 0u};
    if (host_call_encode(wire.data(), &metadata))
        throw std::invalid_argument("host call: invalid chunk");
    std::copy_n(reply.data.begin() + offset, length, wire.begin() + HOST_CALL_HEADER_SIZE);
    return wire;
}
}
