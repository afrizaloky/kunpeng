#include "RestAPIHost.h"
#include "TlsSessionService.h"
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <system_error>
#include <memory>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #expr, errno); std::abort(); } } while (false)
namespace {
using namespace std::chrono_literals;
using kunpeng::SessionId;
using Bytes = std::vector<unsigned char>;
constexpr auto bound = 5s;

struct Client {
    int fd;
    explicit Client(std::uint16_t port) : fd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) {
        CHECK(fd >= 0);
        int window = 4096;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &window, sizeof(window)) == 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        CHECK(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
        CHECK(connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    ~Client() { CHECK(::close(fd) == 0); }
    void send(unsigned char byte) { CHECK(::send(fd, &byte, 1, MSG_NOSIGNAL) == 1); }
    Bytes receive(std::size_t size) {
        Bytes result;
        const auto deadline = std::chrono::steady_clock::now() + bound;
        while (result.size() < size) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            CHECK(remaining.count() > 0);
            pollfd event{fd, POLLIN, 0};
            const int ready = poll(&event, 1, static_cast<int>(remaining.count()));
            if (ready < 0 && errno == EINTR) continue;
            CHECK(ready == 1);
            unsigned char buffer[4096];
            const auto count = recv(fd, buffer, std::min(sizeof(buffer), size - result.size()), MSG_DONTWAIT);
            if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            CHECK(count > 0);
            result.insert(result.end(), buffer, buffer + count);
        }
        return result;
    }
    void eof() {
        pollfd event{fd, POLLIN, 0};
        CHECK(poll(&event, 1, 5000) == 1);
        unsigned char byte;
        CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == 0);
    }
};

class Backend final : public kunpeng::TlsSessionService {
public:
    struct Session { bool active = false; unsigned chunks = 0; Bytes input; unsigned closes = 0; };
    std::mutex mutex;
    std::condition_variable changed;
    std::map<SessionId, Session> sessions;
    bool released = false;
    unsigned blocked = 0;
    unsigned entered = 0;
    unsigned blockCount = 1;
    bool fatal = false;
    bool stream = false;
    bool blockOpen = false;
    unsigned char reject = 0;
    bool oversized = false;
    bool failClose = false;
    unsigned hostMode = 0, supplies = 0;
    bool blockSupply = false;
    Bytes certificate() override { return {'P', 'E', 'M'}; }
    template<class Predicate> void await(Predicate predicate) {
        std::unique_lock<std::mutex> lock(mutex);
        CHECK(changed.wait_for(lock, bound, predicate));
    }
    void release() {
        std::lock_guard<std::mutex> lock(mutex);
        released = true;
        changed.notify_all();
    }
    void gate(std::unique_lock<std::mutex>& lock) {
        ++blocked;
        changed.notify_all();
        CHECK(changed.wait_for(lock, bound, [&] { return released; }));
    }
    void open(SessionId id) override {
        std::unique_lock<std::mutex> lock(mutex);
        CHECK(sessions.emplace(id, Session{}).second);
        if (blockOpen) gate(lock);
        changed.notify_all();
    }
    kunpeng::ProcessResult process(SessionId id, const Bytes& input) override {
        std::unique_lock<std::mutex> lock(mutex);
        auto& session = sessions.at(id);
        CHECK(!session.active);
        CHECK(session.closes == 0);
        session.active = true;
        kunpeng::ProcessResult result{{}, true, false, false, false};
        if (!input.empty()) {
            session.input.insert(session.input.end(), input.begin(), input.end());
            if (++entered <= blockCount) gate(lock);
            if (input.front() == reject) {
                session.active = false;
                changed.notify_all();
                throw std::runtime_error("client process failure");
            }
            if (!stream) result.output = Bytes(oversized ? 65537 : input.size(), 0xa7);
        }
        if (stream && (!input.empty() || session.chunks != 0)) {
            CHECK(session.chunks < 64);
            result.output = Bytes(65536, static_cast<unsigned char>(++session.chunks));
            result.moreOutput = session.chunks < 64;
            result.closed = !result.moreOutput && !fatal;
            result.fatal = !result.moreOutput && fatal;
        }
        if (hostMode && !input.empty() && input.front() == 0x44) {
            result.output.clear();
            result.hostRequest = kunpeng::HostDataRequest{hostMode == 2 ? 2u : 1u, 7};
        }
        session.active = false;
        changed.notify_all();
        return result;
    }
    kunpeng::ProcessResult supplyHostData(SessionId id, kunpeng::HostDataRequest request,
        const Bytes& data) override {
        std::unique_lock<std::mutex> lock(mutex);
        auto& session = sessions.at(id);
        CHECK(!session.active && session.closes == 0);
        CHECK(request.operation == 1 && request.id == 7);
        const std::string expected = "Public demo data from CA.\n";
        host_call_chunk chunk{};
        CHECK(host_call_decode(data.data(), data.size(), &chunk) == 0);
        CHECK(chunk.operation == request.operation && chunk.id == request.id && chunk.final);
        CHECK(Bytes(data.begin() + HOST_CALL_HEADER_SIZE, data.end()) == Bytes(expected.begin(), expected.end()));
        ++supplies;
        if (blockSupply) gate(lock);
        if (hostMode == 4) throw std::runtime_error("uncertain supply failure");
        kunpeng::ProcessResult result{{0xb8}, true, false, false, false};
        if (hostMode == 3) result.hostRequest = request;
        return result;
    }
    void close(SessionId id) override {
        std::lock_guard<std::mutex> lock(mutex);
        auto& session = sessions.at(id);
        CHECK(!session.active);
        CHECK(++session.closes == 1);
        changed.notify_all();
        if (failClose) throw std::runtime_error("close failure");
    }
    void cleaned(std::size_t count) {
        std::lock_guard<std::mutex> lock(mutex);
        CHECK(sessions.size() == count);
        for (const auto& entry : sessions) CHECK(entry.second.closes == 1);
    }
};

struct RunningHost {
    kunpeng::HostCallDispatcher dispatcher;
    kunpeng::RestAPIHost::Options configure(kunpeng::RestAPIHost::Options options) {
        dispatcher.registerHandler(1, [](const kunpeng::HostCallRequest&) {
            const std::string data = "Public demo data from CA.\n";
            return kunpeng::HostCallReply{kunpeng::HostCallStatus::Success, {data.begin(), data.end()}};
        });
        options.hostDispatcher = &dispatcher;
        return options;
    }
    kunpeng::RestAPIHost host;
    std::promise<void> done;
    std::future<void> completion = done.get_future();
    std::thread thread;
    RunningHost(Backend& backend, kunpeng::RestAPIHost::Options options)
        : host(backend, configure(options)), thread([this] {
            try { host.run(); done.set_value(); }
            catch (...) { done.set_exception(std::current_exception()); }
        }) { CHECK(host.waitUntilRunning(bound)); CHECK(host.boundPort() != 0); }
    void join() {
        CHECK(completion.wait_for(bound) == std::future_status::ready);
        thread.join();
        completion.get();
    }
    ~RunningHost() { if (thread.joinable()) { host.stop(); join(); } }
};
kunpeng::RestAPIHost::Options options() {
    kunpeng::RestAPIHost::Options result;
    result.port = 0;
    return result;
}

// A serialized event loop fails the second read before the first gate is released.
// The second write also exposes overlapping process/close calls on the gated session.
void concurrent_clients_keep_session_operations_serial() {
    Backend backend;
    RunningHost running(backend, options());
    Client first(running.host.boundPort());
    first.send(0x11);
    backend.await([&] { return backend.blocked == 1; });
    first.send(0x22);
    Client second(running.host.boundPort());
    second.send(0x33);
    CHECK(second.receive(1) == Bytes{0xa7});
    backend.release();
    CHECK(first.receive(2) == Bytes(2, 0xa7));
    running.host.stop();
    running.join();
    backend.cleaned(2);
    std::lock_guard<std::mutex> lock(backend.mutex);
    bool found = false;
    for (const auto& entry : backend.sessions) if (entry.second.input == Bytes{0x11, 0x22}) found = true;
    CHECK(found);
}

// One worker is held in open while more clients than the queue cap submit data.
// No accept ordering or TCP packet boundaries are assumed.
void bounded_queue_recovers_without_losing_input() {
    Backend backend;
    backend.blockOpen = true;
    backend.blockCount = 0;
    auto config = options();
    config.workerCount = 1;
    config.maxQueuedJobs = 1;
    RunningHost running(backend, config);
    std::vector<std::unique_ptr<Client>> clients;
    clients.emplace_back(new Client(running.host.boundPort()));
    clients.front()->send(0x40);
    backend.await([&] { return backend.blocked == 1; });
    for (unsigned char i = 1; i < 6; ++i) clients.emplace_back(new Client(running.host.boundPort()));
    for (std::size_t i = 1; i < clients.size(); ++i) clients[i]->send(static_cast<unsigned char>(0x40 + i));
    backend.release();
    for (const auto& client : clients) CHECK(client->receive(1) == Bytes{0xa7});
    running.host.stop();
    running.join();
    backend.cleaned(6);
    std::map<unsigned char, unsigned> inputs;
    for (const auto& entry : backend.sessions) {
        CHECK(entry.second.input.size() == 1);
        ++inputs[entry.second.input.front()];
    }
    for (unsigned char i = 0x40; i < 0x46; ++i) CHECK(inputs.at(i) == 1);
}

// Four MiB exceeds the outbound cap and uses a small advertised receive window.
// Exact bytes and EOF protect drain semantics, without claiming a particular EAGAIN.
void terminal_output_drains(bool fatal) {
    Backend backend;
    backend.stream = true;
    backend.fatal = fatal;
    RunningHost running(backend, options());
    Client client(running.host.boundPort());
    client.send(0x71);
    backend.await([&] { return backend.blocked == 1; });
    backend.release();
    for (unsigned char i = 1; i <= 64; ++i) CHECK(client.receive(65536) == Bytes(65536, i));
    client.eof();
    running.host.stop();
    running.join();
    backend.cleaned(1);
}

void stop_waits_for_backend_then_cleans_once() {
    Backend backend;
    RunningHost running(backend, options());
    Client client(running.host.boundPort());
    client.send(0x81);
    backend.await([&] { return backend.blocked == 1; });
    running.host.stop();
    CHECK(running.completion.wait_for(0ms) == std::future_status::timeout);
    backend.release();
    running.join();
    backend.cleaned(1);
    client.eof();
}
void stop_cancels_unentered_clients() {
    Backend backend;
    backend.blockOpen = true;
    auto config = options();
    config.workerCount = 1;
    config.maxQueuedJobs = 1;
    RunningHost running(backend, config);
    Client active(running.host.boundPort());
    active.send(0x91);
    backend.await([&] { return backend.blocked == 1; });
    Client queued(running.host.boundPort());
    queued.send(0x92);
    CHECK(shutdown(queued.fd, SHUT_WR) == 0);
    running.host.stop();
    active.eof();
    CHECK(running.completion.wait_for(0ms) == std::future_status::timeout);
    backend.release();
    running.join();
    backend.cleaned(1);
    CHECK(backend.entered == 1);
    CHECK(backend.sessions.begin()->second.input == Bytes{0x91});
}

void client_process_failure_is_isolated() {
    Backend backend;
    backend.blockCount = 0;
    backend.reject = 0xa1;
    RunningHost running(backend, options());
    Client bad(running.host.boundPort());
    bad.send(0xa1);
    bad.eof();
    Client healthy(running.host.boundPort());
    healthy.send(0xa2);
    CHECK(healthy.receive(1) == Bytes{0xa7});
    running.host.stop();
    running.join();
    backend.cleaned(2);
}

void oversized_backend_output_is_rejected() {
    Backend backend;
    backend.blockCount = 0;
    backend.oversized = true;
    RunningHost running(backend, options());
    Client client(running.host.boundPort());
    client.send(0xb1);
    client.eof();
    running.host.stop();
    running.join();
    backend.cleaned(1);
}

void close_failure_is_reported_once() {
    Backend backend;
    backend.blockCount = 0;
    backend.failClose = true;
    RunningHost running(backend, options());
    Client client(running.host.boundPort());
    client.send(0xc1);
    CHECK(client.receive(1) == Bytes{0xa7});
    running.host.stop();
    bool failed = false;
    try { running.join(); }
    catch (const std::runtime_error&) { failed = true; }
    CHECK(failed);
    backend.cleaned(1);
}
void stop_before_run_does_not_start_workers() {
    Backend backend;
    kunpeng::RestAPIHost host(backend, options());
    host.stop();
    host.run();
    CHECK(!host.waitUntilRunning(0ms));
    CHECK(host.boundPort() == 0);
    backend.cleaned(0);
}

void bind_failure_cleans_startup() {
    Backend backend;
    RunningHost running(backend, options());
    auto config = options();
    config.port = running.host.boundPort();
    kunpeng::RestAPIHost conflicting(backend, config);
    bool failed = false;
    try { conflicting.run(); }
    catch (const std::system_error& error) {
        CHECK(error.code().value() == EADDRINUSE);
        failed = true;
    }
    CHECK(failed);
    CHECK(!conflicting.waitUntilRunning(0ms));
    running.host.stop();
    running.join();
    backend.cleaned(0);
}

void accept_flood_does_not_starve_stop() {
    Backend backend;
    auto config = options();
    config.maxConnections = 1;
    RunningHost running(backend, config);
    Client active(running.host.boundPort());
    active.send(0xd1);
    backend.await([&] { return backend.blocked == 1; });
    std::atomic<bool> finish{false};
    std::promise<void> connected;
    auto ready = connected.get_future();
    auto flood = std::async(std::launch::async, [&] {
        bool announced = false;
        while (!finish.load()) {
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
            CHECK(fd >= 0);
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_port = htons(running.host.boundPort());
            CHECK(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
            const int result = connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
            CHECK(result == 0 || errno == EINPROGRESS || errno == ECONNREFUSED);
            if (!announced) { connected.set_value(); announced = true; }
            CHECK(::close(fd) == 0);
        }
    });
    CHECK(ready.wait_for(bound) == std::future_status::ready);
    running.host.stop();
    active.eof();
    backend.release();
    running.join();
    finish.store(true);
    CHECK(flood.wait_for(bound) == std::future_status::ready);
    flood.get();
    backend.cleaned(1);
}
void host_supply_is_bounded_and_failure_cleans_once() {
    for (unsigned mode = 1; mode <= 4; ++mode) {
        Backend backend;
        backend.blockCount = 0;
        backend.hostMode = mode;
        RunningHost running(backend, options());
        Client client(running.host.boundPort());
        client.send(0x44);
        if (mode == 1) CHECK(client.receive(1) == Bytes({0xb8}));
        else client.eof();
        running.host.stop();
        running.join();
        backend.cleaned(1);
        CHECK(backend.supplies == (mode == 2 ? 0u : 1u));
    }
}
void supply_wait_does_not_block_other_clients() {
    Backend backend;
    backend.blockCount = 0;
    backend.hostMode = 1;
    backend.blockSupply = true;
    RunningHost running(backend, options());
    Client first(running.host.boundPort());
    first.send(0x44);
    backend.await([&] { return backend.blocked == 1; });
    Client second(running.host.boundPort());
    second.send(0x55);
    CHECK(second.receive(1) == Bytes{0xa7});
    backend.release();
    CHECK(first.receive(1) == Bytes({0xb8}));
    running.host.stop();
    running.join();
    backend.cleaned(2);
}
} // namespace
int main() {
    host_supply_is_bounded_and_failure_cleans_once();
    supply_wait_does_not_block_other_clients();
    concurrent_clients_keep_session_operations_serial();
    bounded_queue_recovers_without_losing_input();
    terminal_output_drains(false);
    terminal_output_drains(true);
    stop_waits_for_backend_then_cleans_once();
    stop_cancels_unentered_clients();
    client_process_failure_is_isolated();
    oversized_backend_output_is_rejected();
    close_failure_is_reported_once();
    stop_before_run_does_not_start_workers();
    bind_failure_cleans_startup();
    accept_flood_does_not_starve_stop();
    std::puts("host concurrency tests passed");
}
