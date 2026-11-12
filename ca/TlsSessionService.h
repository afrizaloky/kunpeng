#ifndef KUNPENG_TLS_SESSION_SERVICE_H
#define KUNPENG_TLS_SESSION_SERVICE_H

#include <cstdint>
#include <vector>
#include <optional>
#include <functional>
#include "host_call_dispatcher.h"

namespace kunpeng {

using SessionId = std::uint64_t;

using HostDataRequest = HostCallRequest;
using HostDataStatus = HostCallStatus;
using HostDataReply = HostCallReply;
using HostDataHandler = HostCallHandler;

struct ProcessResult {
    std::vector<unsigned char> output;
    bool handshake;
    bool moreOutput;
    bool closed;
    bool fatal;
    std::optional<HostDataRequest> hostRequest{};
};

// Transport/protocol failures throw std::runtime_error. TLS fatal responses
// remain ProcessResult values so callers can drain any pending alert output.
// open/process/close map architecturally to kripta-key AbstractRestSessionService
// restSessionOpen/restSessionProcess/restSessionClose (not a drop-in API).
// Vectors provide standalone owned buffers; moreOutput/closed/handshake map to
// hasMoreData/shouldClose/handshakeComplete without importing kk core types.
class TlsSessionService {
public:
    virtual ~TlsSessionService() = default;
    // Public PEM bytes including exactly one terminating NUL.
    virtual std::vector<unsigned char> certificate() = 0;
    virtual void open(SessionId id) = 0;
    virtual ProcessResult process(SessionId id,
        const std::vector<unsigned char>& input) = 0;
    virtual ProcessResult supplyHostData(SessionId id, HostDataRequest request,
        const std::vector<unsigned char>& data) = 0;
    virtual void close(SessionId id) = 0;
};

} // namespace kunpeng

#endif
