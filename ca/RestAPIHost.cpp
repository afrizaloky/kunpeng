#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "RestAPIHost.h"
#include "TlsSessionService.h"
#include "tls_protocol.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <climits>
#include <condition_variable>
#include <deque>
#include <exception>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

namespace kunpeng {
namespace {
using Clock = std::chrono::steady_clock;
void systemFailure(const char* operation) {
    throw std::system_error(errno, std::generic_category(), operation);
}
void closeFd(int& fd) noexcept {
    if (fd >= 0) { ::close(fd); fd = -1; }
}
void wake(int fd) noexcept {
    const std::uint64_t one = 1;
    while (::write(fd, &one, sizeof(one)) < 0 && errno == EINTR) {}
}
}

struct RestAPIHost::Impl {
    enum class Kind { OpenAndProcess, Process, Close };
    struct Job {
        Kind kind{Kind::Process};
        std::uint64_t id{0};
        std::vector<unsigned char> input;
    };
    struct Completion {
        Kind kind{Kind::Process};
        std::uint64_t id{0};
        bool opened{false};
        bool handshake{false}, more{false}, closed{false}, fatal{false};
        std::vector<unsigned char> output;
        std::exception_ptr error;
    };
    struct Connection {
        int fd{-1};
        bool registered{false}, busy{false}, opened{false};
        bool terminal{false}, final{false}, more{false}, handshake{false};
        Clock::time_point accepted{Clock::now()}, activity{accepted};
        std::vector<unsigned char> input, output;
        std::size_t offset{0};
    };
    TlsSessionService& service;
    Options options;
    std::atomic<bool> stopping{false};
    std::atomic<std::uint16_t> port{0};
    std::atomic<std::size_t> inputBytes{0};

    std::mutex lifecycle;
    std::condition_variable lifecycleCv;
    bool started{false}, running{false}, finished{false};
    int notification{-1}, listener{-1}, epoll{-1};
    std::mutex queueMutex;
    std::condition_variable queueCv;
    bool workersDone{false};
    std::deque<Job> jobs;
    // One outstanding job per connection bounds close storage during teardown.
    std::vector<Job> closes;
    // Preallocated slots: a connection has at most one outstanding operation,
    // so workers can publish without allocating or blocking on the event loop.
    std::vector<Completion> completions;
    std::size_t completionCount{0}, queuedBytes{0};
    std::vector<std::thread> workers;
    std::unordered_map<std::uint64_t, Connection> connections;
    std::deque<std::uint64_t> order;
    std::uint64_t nextId{2}; // 0 = eventfd, 1 = listener
    std::exception_ptr failure;

    Impl(TlsSessionService& s, Options o) : service(s), options(std::move(o)) {
        if (options.workerCount == 0 || options.maxConnections == 0 ||
            options.maxQueuedJobs == 0 || options.maxQueuedInputBytes == 0 ||
            options.maxOutboundBytes == 0 || options.handshakeTimeout.count() <= 0 ||
            options.idleTimeout.count() <= 0)
            throw std::invalid_argument("RestAPIHost: limits and timeouts must be positive");
        sockaddr_in address{};
        if (::inet_pton(AF_INET, options.bindAddress.c_str(), &address.sin_addr) != 1)
            throw std::invalid_argument("RestAPIHost: bindAddress must be an IPv4 literal");
        completions.resize(options.maxConnections);
        closes.reserve(options.maxConnections);
        workers.reserve(options.workerCount);
    }
    void remember(std::exception_ptr error) noexcept {
        if (!failure) failure = std::move(error);
    }
    void worker() noexcept {
        for (;;) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCv.wait(lock, [&] {
                    return workersDone || !closes.empty() || (!stopping.load() && !jobs.empty());
                });
                if (workersDone && closes.empty() && jobs.empty()) return;
                if (!closes.empty()) {
                    job = std::move(closes.back());
                    closes.pop_back();
                } else {
                    job = std::move(jobs.front());
                    jobs.pop_front();
                }
                queuedBytes -= job.input.size();
            }
            Completion result;
            result.id = job.id;
            result.kind = job.kind;
            try {
                if (job.kind == Kind::Close) {
                    service.close(job.id);
                } else {
                    if (job.kind == Kind::OpenAndProcess) {
                        service.open(job.id);
                        result.opened = true;
                    }
                    auto processed = service.process(job.id, job.input);
                    if (processed.hostRequest) {
                        const auto request = *processed.hostRequest;
                        if (request.operation != TLS_PROTOCOL_HOST_OP_DEMO_DATA || request.id == 0 ||
                            !processed.handshake || processed.closed || processed.fatal ||
                            processed.output.size() > TLS_PROTOCOL_CAPACITY)
                            throw std::runtime_error("RestAPIHost: invalid host request");
                        static const std::string publicData = "Public demo data from CA.\n";
                        auto supplied = service.supplyHostData(job.id, request,
                            std::vector<unsigned char>(publicData.begin(), publicData.end()));
                        if (supplied.hostRequest ||
                            supplied.output.size() > TLS_PROTOCOL_CAPACITY - processed.output.size())
                            throw std::runtime_error("RestAPIHost: repeated request or excess output");
                        processed.output.insert(processed.output.end(), supplied.output.begin(), supplied.output.end());
                        supplied.output = std::move(processed.output);
                        processed = std::move(supplied);
                    }
                    result.handshake = processed.handshake;
                    result.more = processed.moreOutput;
                    result.closed = processed.closed;
                    result.fatal = processed.fatal;
                    if (processed.output.size() > TLS_PROTOCOL_CAPACITY ||
                        processed.output.size() > options.maxOutboundBytes)
                        throw std::runtime_error("RestAPIHost: backend output exceeds capacity");
                    result.output = std::move(processed.output);
                }
            } catch (...) { result.error = std::current_exception(); }
            inputBytes.fetch_sub(job.input.size());
            job.input.clear();
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                completions[completionCount++] = std::move(result);
            }
            queueCv.notify_all();
            // notification stays alive until all workers are joined.
            wake(notification);
        }
    }
    void retire(Connection& c) noexcept {
        if (c.registered) {
            ::epoll_ctl(epoll, EPOLL_CTL_DEL, c.fd, nullptr);
            c.registered = false;
        }
        closeFd(c.fd);
        c.terminal = true;
        inputBytes.fetch_sub(c.input.size());
        c.input.clear();
        c.output.clear();
        c.offset = 0;
    }
    void interest(std::uint64_t id, Connection& c) {
        if (c.fd < 0) return;
        std::uint32_t flags = 0;
        if (!c.busy && !c.final && !c.more && c.input.empty() && c.output.empty() &&
            inputBytes.load() < options.maxQueuedInputBytes)
            flags |= EPOLLIN | EPOLLRDHUP;
        if (c.offset < c.output.size()) flags |= EPOLLOUT;
        if (flags == 0) {
            if (c.registered && ::epoll_ctl(epoll, EPOLL_CTL_DEL, c.fd, nullptr) < 0)
                systemFailure("epoll_ctl DEL");
            c.registered = false;
            return;
        }
        epoll_event event{};
        event.events = flags;
        event.data.u64 = id;
        if (::epoll_ctl(epoll, c.registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, c.fd, &event) < 0)
            systemFailure("epoll_ctl connection");
        c.registered = true;
    }
    void collect() {
        std::lock_guard<std::mutex> lock(queueMutex);
        for (std::size_t i = 0; i < completionCount; ++i) {
            Completion result = std::move(completions[i]);
            auto found = connections.find(result.id);
            if (found == connections.end()) continue;
            auto& c = found->second;
            c.busy = false;
            if (result.kind == Kind::Close) {
                c.opened = false; // exactly one close attempt, including throws
                if (result.error) remember(result.error);
                continue;
            }
            c.opened = c.opened || result.opened;
            if (result.error) {
                // Open/process failures belong to this client, not the host.
                retire(c);
                continue;
            }
            if (c.terminal) continue;
            c.handshake = c.handshake || result.handshake;
            c.more = result.more;
            c.final = c.final || result.closed || result.fatal;
            c.output = std::move(result.output);
            c.offset = 0;
        }
        completionCount = 0;
    }
    void pump() {
        const auto count = order.size();
        for (std::size_t i = 0; i < count; ++i) {
            auto id = order.front(); order.pop_front();
            auto found = connections.find(id);
            if (found == connections.end()) continue;
            auto& c = found->second;
            if (!c.busy && (c.terminal || (c.final && !c.more && c.output.empty()))) {
                retire(c);
                if (!c.opened) { connections.erase(found); continue; }
                std::lock_guard<std::mutex> lock(queueMutex);
                closes.push_back(Job{Kind::Close, id, {}});
                c.busy = true;
                queueCv.notify_all();
            } else if (!c.busy && !c.terminal && c.output.empty() &&
                       (!c.input.empty() || c.more)) {
                std::lock_guard<std::mutex> lock(queueMutex);
                if (jobs.size() < options.maxQueuedJobs &&
                    c.input.size() <= options.maxQueuedInputBytes - queuedBytes) {
                    const auto bytes = c.input.size();
                    jobs.push_back(Job{c.opened ? Kind::Process : Kind::OpenAndProcess,
                                       id, std::move(c.input)});
                    queuedBytes += bytes;
                    c.input.clear();
                    c.busy = true;
                    c.more = false;
                    queueCv.notify_all();
                }
            }
            interest(id, c);
            order.push_back(id);
        }
        // Rotate the first contender, including when a queue remains saturated.
        if (!order.empty()) { order.push_back(order.front()); order.pop_front(); }
    }
    void acceptConnections() {
        for (unsigned attempt = 0; attempt < 64 && !stopping.load(); ++attempt) {
            int fd = ::accept4(listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                if (errno == ECONNABORTED || errno == EPROTO) continue;
                systemFailure("accept4");
            }
            if (connections.size() >= options.maxConnections) { closeFd(fd); continue; }
            try {
                int one = 1;
                if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0)
                    systemFailure("TCP_NODELAY");
                if (nextId == std::numeric_limits<std::uint64_t>::max())
                    throw std::runtime_error("RestAPIHost: session ID exhausted");
                const auto id = nextId++;
                auto inserted = connections.try_emplace(id);
                inserted.first->second.fd = fd;
                fd = -1;
                order.push_back(id);
                interest(id, inserted.first->second);
            } catch (...) { closeFd(fd); throw; }
        }
    }
    void socketEvent(std::uint64_t id, std::uint32_t flags) {
        auto found = connections.find(id);
        if (found == connections.end()) return;
        auto& c = found->second;
        if (c.fd < 0) return;
        if (flags & EPOLLERR) { retire(c); return; }
        if (flags & EPOLLOUT) {
            while (c.offset < c.output.size()) {
                auto sent = ::send(c.fd, c.output.data() + c.offset,
                                   c.output.size() - c.offset, MSG_NOSIGNAL);
                if (sent > 0) { c.offset += static_cast<std::size_t>(sent); c.activity = Clock::now(); }
                else if (sent < 0 && errno == EINTR) continue;
                else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                else { retire(c); return; }
            }
            if (c.offset == c.output.size()) { c.output.clear(); c.offset = 0; }
        }
        if (!c.busy && !c.final && !c.more && c.input.empty() && c.output.empty() &&
            (flags & (EPOLLIN | EPOLLRDHUP | EPOLLHUP))) {
            std::array<unsigned char, 16384> buffer{};
            ssize_t received;
            const auto available = options.maxQueuedInputBytes - inputBytes.load();
            if (available == 0) return;
            do { received = ::recv(c.fd, buffer.data(),
                                  std::min(buffer.size(), available), 0); }
            while (received < 0 && errno == EINTR);
            if (received > 0) {
                c.input.assign(buffer.begin(), buffer.begin() + received);
                inputBytes.fetch_add(c.input.size());
                c.activity = Clock::now();
            } else if (received == 0) { c.final = true; }
            else if (errno != EAGAIN && errno != EWOULDBLOCK) retire(c);
        } else if (flags & EPOLLHUP) {
            // Full hangup cannot make write progress. Remove it rather than spin.
            retire(c);
        }
    }
    void setup() {
        epoll = ::epoll_create1(EPOLL_CLOEXEC);
        if (epoll < 0) systemFailure("epoll_create1");
        {
            std::lock_guard<std::mutex> lock(lifecycle);
            notification = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
            if (notification < 0) systemFailure("eventfd");
        }
        epoll_event event{};
        event.events = EPOLLIN;
        event.data.u64 = 0;
        if (::epoll_ctl(epoll, EPOLL_CTL_ADD, notification, &event) < 0) systemFailure("epoll_ctl eventfd");
        listener = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (listener < 0) systemFailure("socket");
        int one = 1;
        if (::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) systemFailure("SO_REUSEADDR");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(options.port);
        ::inet_pton(AF_INET, options.bindAddress.c_str(), &address.sin_addr);
        if (::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) systemFailure("bind");
        if (::listen(listener, SOMAXCONN) < 0) systemFailure("listen");
        socklen_t length = sizeof(address);
        if (::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) < 0) systemFailure("getsockname");
        port.store(ntohs(address.sin_port));
        event.data.u64 = 1;
        if (::epoll_ctl(epoll, EPOLL_CTL_ADD, listener, &event) < 0) systemFailure("epoll_ctl listener");
        for (std::size_t i = 0; i < options.workerCount; ++i)
            workers.emplace_back([this] { worker(); });
    }
    void loop() {
        std::array<epoll_event, 64> events{};
        while (!stopping.load()) {
            collect();
            pump();
            auto now = Clock::now();
            auto deadline = Clock::time_point::max();
            for (auto& entry : connections) {
                auto& c = entry.second;
                if (c.terminal) continue;
                auto at = c.activity + options.idleTimeout;
                if (!c.handshake) at = std::min(at, c.accepted + options.handshakeTimeout);
                if (at <= now) retire(c);
                else deadline = std::min(deadline, at);
            }
            pump();
            int timeout = -1;
            if (deadline != Clock::time_point::max()) {
                auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()).count();
                timeout = static_cast<int>(std::min<long long>(INT_MAX, std::max<long long>(0, remaining)));
            }
            int count = ::epoll_wait(epoll, events.data(), static_cast<int>(events.size()), timeout);
            if (count < 0) { if (errno == EINTR) continue; systemFailure("epoll_wait"); }
            for (int i = 0; i < count && !stopping.load(); ++i) {
                auto& event = events[static_cast<std::size_t>(i)];
                if (event.data.u64 == 0) {
                    std::uint64_t value;
                    while (::read(notification, &value, sizeof(value)) < 0 && errno == EINTR) {}
                } else if (event.data.u64 == 1) acceptConnections();
                else socketEvent(event.data.u64, event.events);
            }
        }
    }
    // Cleanup uses the same workers but does not depend on epoll remaining usable.
    void shutdown() {
        closeFd(listener);
        for (auto& entry : connections) retire(entry.second);
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            stopping.store(true);
            for (const auto& job : jobs) {
                queuedBytes -= job.input.size();
                inputBytes.fetch_sub(job.input.size());
                connections.at(job.id).busy = false;
            }
            jobs.clear();
        }
        while (!connections.empty()) {
            collect();
            for (auto it = connections.begin(); it != connections.end();) {
                auto& c = it->second;
                if (c.busy) { ++it; continue; }
                if (c.opened) {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    closes.push_back(Job{Kind::Close, it->first, {}});
                    c.busy = true;
                    queueCv.notify_all();
                    ++it;
                } else it = connections.erase(it);
            }
            if (!connections.empty()) {
                // Worker publication wakes this predicate without polling.
                std::unique_lock<std::mutex> lock(queueMutex);
                queueCv.wait(lock, [&] { return completionCount != 0; });
            }
        }
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            workersDone = true;
        }
        queueCv.notify_all();
        for (auto& thread : workers) if (thread.joinable()) thread.join();
        workers.clear();
        closeFd(epoll);
        {
            std::lock_guard<std::mutex> lock(lifecycle);
            closeFd(notification);
            running = false;
            finished = true;
        }
        lifecycleCv.notify_all();
    }
};

RestAPIHost::RestAPIHost(TlsSessionService& service, Options options)
    : impl_(std::make_unique<Impl>(service, std::move(options))) {}
RestAPIHost::~RestAPIHost() { stop(); }
void RestAPIHost::stop() noexcept {
    {
        std::lock_guard<std::mutex> lock(impl_->queueMutex);
        impl_->stopping.store(true);
    }
    std::lock_guard<std::mutex> lock(impl_->lifecycle);
    if (impl_->notification >= 0) wake(impl_->notification);
}
bool RestAPIHost::waitUntilRunning(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(impl_->lifecycle);
    impl_->lifecycleCv.wait_for(lock, timeout, [&] { return impl_->running || impl_->finished; });
    return impl_->running;
}
std::uint16_t RestAPIHost::boundPort() const noexcept { return impl_->port.load(); }
void RestAPIHost::run() {
    {
        std::lock_guard<std::mutex> lock(impl_->lifecycle);
        if (impl_->started) throw std::logic_error("RestAPIHost::run is single-use");
        impl_->started = true;
    }
    try {
        if (!impl_->stopping.load()) {
            impl_->setup();
            {
                std::lock_guard<std::mutex> lock(impl_->lifecycle);
                impl_->running = true;
            }
            impl_->lifecycleCv.notify_all();
            impl_->loop();
        }
    } catch (...) { impl_->remember(std::current_exception()); }
    impl_->shutdown();
    if (impl_->failure) std::rethrow_exception(impl_->failure);
}
} // namespace kunpeng
