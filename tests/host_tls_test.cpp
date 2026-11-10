#include "../ca/RestAPIHost.h"
#include "../ca/TlsSessionService.h"
#include "../include/tls_engine.h"
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); ERR_print_errors_fp(stderr); std::abort(); } } while (false)
namespace {
using namespace std::chrono_literals;
using Bytes = std::vector<unsigned char>;
using kunpeng::SessionId;
int randomBytes(void*, unsigned char* out, std::size_t size) {
    while (size) {
        const auto count = getrandom(out, size, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        out += count;
        size -= static_cast<std::size_t>(count);
    }
    return 0;
}
class Engine final : public kunpeng::TlsSessionService {
    tls_identity* identity = nullptr;
    std::map<SessionId, tls_connection*> sessions;
    std::mutex mutex;
    std::condition_variable changed;
    std::size_t inputCalls = 0;
    std::size_t opened = 0, destroyed = 0;
public:
    Engine() { CHECK(tls_identity_create(&identity, randomBytes, nullptr) == 0); }
    ~Engine() { CHECK(sessions.empty()); tls_identity_destroy(identity); }
    Bytes certificate() override {
        std::lock_guard<std::mutex> lock(mutex);
        Bytes pem(TLS_IO_CAPACITY);
        std::size_t written = 0;
        CHECK(tls_identity_certificate(identity, pem.data(), pem.size(), &written) == 0);
        pem.resize(written);
        CHECK(pem.back() == 0);
        return pem;
    }
    void open(SessionId id) override {
        std::lock_guard<std::mutex> lock(mutex);
        tls_connection* connection = nullptr;
        CHECK(tls_connection_create(&connection, identity) == 0);
        CHECK(sessions.emplace(id, connection).second);
        ++opened;
    }
    kunpeng::ProcessResult process(SessionId id, const Bytes& input) override {
        std::lock_guard<std::mutex> lock(mutex);
        kunpeng::ProcessResult result{Bytes(TLS_IO_CAPACITY), false, false, false, false};
        std::size_t written = 0;
        unsigned flags = 0;
        const int status = tls_connection_process(sessions.at(id), input.data(), input.size(),
            result.output.data(), result.output.size(), &written, &flags);
        result.output.resize(written);
        result.handshake = (flags & TLS_FLAG_HANDSHAKE) != 0;
        result.moreOutput = (flags & TLS_FLAG_MORE_OUTPUT) != 0;
        result.closed = (flags & TLS_FLAG_CLOSED) != 0;
        result.fatal = status < 0;
        if (!input.empty()) { ++inputCalls; changed.notify_all(); }
        return result;
    }
    void close(SessionId id) override {
        std::lock_guard<std::mutex> lock(mutex);
        CHECK(sessions.count(id) == 1);
        tls_connection_destroy(sessions.at(id));
        sessions.erase(id);
        ++destroyed;
        changed.notify_all();
    }
    void awaitPartialHello() {
        std::unique_lock<std::mutex> lock(mutex);
        CHECK(changed.wait_for(lock, 5s, [&] { return inputCalls != 0; }));
        CHECK(opened == 1);
    }
    void checkCleanup() {
        std::lock_guard<std::mutex> lock(mutex);
        CHECK(opened == 3);
        CHECK(destroyed == opened);
        CHECK(sessions.empty());
    }
};
struct Host {
    kunpeng::RestAPIHost host;
    std::future<void> finished;
    explicit Host(Engine& engine) : host(engine, config()),
        finished(std::async(std::launch::async, [&] { host.run(); })) {
        CHECK(host.waitUntilRunning(5s));
    }
    static kunpeng::RestAPIHost::Options config() {
        kunpeng::RestAPIHost::Options value;
        value.port = 0;
        return value;
    }
    ~Host() { if (finished.valid()) stop(); }
    void stop() {
        host.stop();
        CHECK(finished.wait_for(5s) == std::future_status::ready);
        finished.get();
    }
};
struct Client {
    int fd;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl;
    Client(SSL_CTX* context, std::uint16_t port)
        : fd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)), ssl(SSL_new(context), SSL_free) {
        CHECK(fd >= 0 && ssl);
        timeval timeout{5, 0};
        CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        CHECK(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
        CHECK(connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        CHECK(SSL_set1_host(ssl.get(), "localhost") == 1);
        CHECK(SSL_set_tlsext_host_name(ssl.get(), "localhost") == 1);
        BIO* incoming = BIO_new(BIO_s_mem());
        BIO* outgoing = BIO_new(BIO_s_mem());
        CHECK(incoming && outgoing);
        SSL_set_bio(ssl.get(), incoming, outgoing);
        SSL_set_connect_state(ssl.get());
    }
    ~Client() { CHECK(::close(fd) == 0); }
    void send(const Bytes& bytes) {
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const auto count = ::send(fd, bytes.data() + offset, bytes.size() - offset, MSG_NOSIGNAL);
            if (count < 0 && errno == EINTR) continue;
            CHECK(count > 0);
            offset += static_cast<std::size_t>(count);
        }
    }
    Bytes hello() {
        CHECK(SSL_do_handshake(ssl.get()) == -1);
        CHECK(SSL_get_error(ssl.get(), -1) == SSL_ERROR_WANT_READ);
        Bytes result(static_cast<std::size_t>(BIO_ctrl_pending(SSL_get_wbio(ssl.get()))));
        CHECK(result.size() > 5);
        CHECK(BIO_read(SSL_get_wbio(ssl.get()), result.data(), static_cast<int>(result.size())) == static_cast<int>(result.size()));
        return result;
    }
    void exchange() {
        unsigned char buffer[65536];
        BIO* output = SSL_get_wbio(ssl.get());
        while (BIO_ctrl_pending(output)) {
            const int count = BIO_read(output, buffer, sizeof(buffer));
            CHECK(count > 0);
            send(Bytes(buffer, buffer + count));
        }
        ssize_t count;
        do { count = recv(fd, buffer, sizeof(buffer), 0); } while (count < 0 && errno == EINTR);
        CHECK(count > 0);
        CHECK(BIO_write(SSL_get_rbio(ssl.get()), buffer, static_cast<int>(count)) == count);
    }
    void request() {
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        for (;;) {
            CHECK(std::chrono::steady_clock::now() < deadline);
            const int result = SSL_do_handshake(ssl.get());
            if (result == 1) break;
            CHECK(SSL_get_error(ssl.get(), result) == SSL_ERROR_WANT_READ);
            exchange();
        }
        CHECK(SSL_get_verify_result(ssl.get()) == X509_V_OK);
        CHECK(SSL_version(ssl.get()) == TLS1_2_VERSION);
        constexpr char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        CHECK(SSL_write(ssl.get(), request, sizeof(request) - 1) == sizeof(request) - 1);
        std::string response;
        for (;;) {
            CHECK(std::chrono::steady_clock::now() < deadline);
            char buffer[4096];
            const int count = SSL_read(ssl.get(), buffer, sizeof(buffer));
            if (count > 0) { response.append(buffer, static_cast<std::size_t>(count)); continue; }
            const int error = SSL_get_error(ssl.get(), count);
            if (error == SSL_ERROR_ZERO_RETURN) break;
            CHECK(error == SSL_ERROR_WANT_READ);
            exchange();
        }
        CHECK(response == "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\nHello from the TEE!\n");
    }
};
} // namespace
int main() {
    Engine engine;
    const Bytes pem = engine.certificate();
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    CHECK(bio);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
    CHECK(certificate);
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    CHECK(context);
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(context.get()), certificate.get()) == 1);
    Host running(engine);
    Client first(context.get(), running.host.boundPort());
    const Bytes hello = first.hello();
    first.send(Bytes(hello.begin(), hello.begin() + 5));
    engine.awaitPartialHello();
    // The first record is incomplete until the second verified exchange finishes.
    Client second(context.get(), running.host.boundPort());
    second.request();
    first.send(Bytes(hello.begin() + 5, hello.end()));
    first.request();
    // Leave an opened session idle: stop must destroy it too.
    Client idle(context.get(), running.host.boundPort());
    idle.send(idle.hello());
    idle.exchange();
    running.stop();
    engine.checkCleanup();
    std::puts("native host TLS test passed");
}
