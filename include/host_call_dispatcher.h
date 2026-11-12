#ifndef HOST_CALL_DISPATCHER_H
#define HOST_CALL_DISPATCHER_H
#include "host_call.h"
#include <cstdint>
#include <functional>
#include <map>
#include <vector>

namespace kunpeng {
struct HostCallRequest {
    std::uint32_t operation;
    std::uint32_t id;
    std::vector<unsigned char> arguments{};
};
enum class HostCallStatus { Success, Error };
struct HostCallReply {
    HostCallStatus status{HostCallStatus::Success};
    std::vector<unsigned char> data;
};
using HostCallHandler = std::function<HostCallReply(const HostCallRequest&)>;
// Register before concurrent dispatch. Handlers must support concurrent calls.
// No wire address is callable; only explicitly registered operation IDs resolve.
class HostCallDispatcher {
public:
    void registerHandler(std::uint32_t operation, HostCallHandler handler);
    HostCallReply dispatch(const HostCallRequest& request) const;
    static std::vector<unsigned char> encodeChunk(const HostCallRequest& request,
        const HostCallReply& reply, std::size_t offset);
private:
    std::map<std::uint32_t, HostCallHandler> handlers_;
};
}
#endif
