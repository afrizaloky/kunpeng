#ifndef KUNPENG_ITRUSTEE_TLS_SESSION_SERVICE_H
#define KUNPENG_ITRUSTEE_TLS_SESSION_SERVICE_H

#include "TlsSessionService.h"

#include <memory>
#include <string>

namespace kunpeng {

// Workers own distinct sessions, but each SDK operation is serialized until
// runtime thread safety is proven. At most eight SDK sessions may be open,
// including temporary certificate sessions. No socket waits occur in the gate.
// Stop and join workers before destruction. The host supplies monotonic IDs;
// only active IDs are retained here.
class ITrusteeTlsSessionService final : public TlsSessionService {
public:
    explicit ITrusteeTlsSessionService(const std::string& taPath);
    ~ITrusteeTlsSessionService() override;

    ITrusteeTlsSessionService(const ITrusteeTlsSessionService&) = delete;
    ITrusteeTlsSessionService& operator=(const ITrusteeTlsSessionService&) = delete;

    std::vector<unsigned char> certificate() override;
    void open(SessionId id) override;
    ProcessResult process(SessionId id,
        const std::vector<unsigned char>& input) override;
    ProcessResult supplyHostData(SessionId id, HostDataRequest request,
        const std::vector<unsigned char>& data) override;
    void close(SessionId id) override;

private:
    ProcessResult invoke(SessionId id, const std::vector<unsigned char>& input,
        std::optional<HostDataRequest> request);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace kunpeng

#endif
