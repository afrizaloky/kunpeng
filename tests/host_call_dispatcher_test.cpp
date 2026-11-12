#include "host_call_dispatcher.h"
#include <cassert>
#include <stdexcept>

int main()
{
    kunpeng::HostCallDispatcher dispatcher;
    dispatcher.registerHandler(42, [](const kunpeng::HostCallRequest& request) {
        assert(request.arguments == std::vector<unsigned char>({0, 255}));
        std::vector<unsigned char> bytes(65536);
        for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<unsigned char>(i % 251);
        return kunpeng::HostCallReply{kunpeng::HostCallStatus::Success, std::move(bytes)};
    });
    dispatcher.registerHandler(91, [](const kunpeng::HostCallRequest&) {
        return kunpeng::HostCallReply{kunpeng::HostCallStatus::Error, {}};
    });
    const kunpeng::HostCallRequest request{42, 7, {0, 255}};
    const auto reply = dispatcher.dispatch(request);
    host_call_budget budget{}; host_call call{};
    assert(host_call_begin(&call, &budget, request.operation, request.id) == 0);
    for (std::size_t offset = 0;;) {
        auto wire = dispatcher.encodeChunk(request, reply, offset);
        assert(host_call_receive(&call, wire.data(), wire.size()) == 0);
        offset += wire.size() - HOST_CALL_HEADER_SIZE;
        if (call.state == HOST_CALL_COMPLETE) break;
    }
    std::size_t offset = 0;
    while (offset < call.size) {
        std::size_t size;
        const auto* bytes = host_call_slice(&call, offset, &size);
        for (std::size_t i = 0; i < size; ++i) assert(bytes[i] == (offset + i) % 251);
        offset += size;
    }
    assert(call.size == 65536);
    host_call_release(&call);
    for (const auto op : {91u, 123u}) {
        kunpeng::HostCallRequest errorRequest{op, 8, {}};
        const auto error = dispatcher.dispatch(errorRequest);
        assert(error.status == kunpeng::HostCallStatus::Error);
        const auto wire = dispatcher.encodeChunk(errorRequest, error, 0);
        assert(host_call_begin(&call, &budget, op, 8) == 0);
        assert(host_call_receive(&call, wire.data(), wire.size()) != 0);
        assert(budget.capacity == 0);
    }
    bool rejected = false;
    try { dispatcher.dispatch({42, 0, {}}); } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
}
