#ifndef KUNPENG_REST_API_HOST_H
#define KUNPENG_REST_API_HOST_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace kunpeng {
class TlsSessionService;

// The service must outlive this host. Join the thread calling run() before
// destroying the host. All backend calls execute on the fixed worker pool.
class RestAPIHost {
public:
    struct Options {
        std::string bindAddress{"127.0.0.1"};
        std::uint16_t port{8443};
        std::size_t workerCount{4};
        std::size_t maxConnections{8};
        std::size_t maxQueuedJobs{16};
        std::size_t maxQueuedInputBytes{1048576};
        std::size_t maxOutboundBytes{262144};
        std::chrono::milliseconds handshakeTimeout{15000};
        std::chrono::milliseconds idleTimeout{15000};
    };

    RestAPIHost(TlsSessionService& service, Options options);
    ~RestAPIHost();
    RestAPIHost(const RestAPIHost&) = delete;
    RestAPIHost& operator=(const RestAPIHost&) = delete;

    // Single-use, blocking; shutdown completes before any exception escapes.
    void run();
    void stop() noexcept;
    bool waitUntilRunning(std::chrono::milliseconds timeout);
    std::uint16_t boundPort() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace kunpeng

#endif
