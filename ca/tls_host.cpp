#include "ITrusteeTlsSessionService.h"
#include "RestAPIHost.h"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

namespace {
void usage(const char* program)
{
    std::printf("Usage: %s --certificate-out FILE [--port PORT] [--bind IPv4] "
                "[--ta PATH] [--workers N] [--max-connections N]\n"
                "Defaults: --port 8443 --bind 127.0.0.1 --workers 4 --max-connections 8\n"
                "Limits: port 1..65535, workers 1..32, max-connections 1..8\n", program);
}

unsigned int positiveNumber(const char* text, unsigned int maximum, const char* option)
{
    unsigned int value = 0;
    const char* end = text + std::strlen(text);
    const auto result = std::from_chars(text, end, value);
    if (result.ec != std::errc{} || result.ptr != end || value == 0 || value > maximum)
        throw std::invalid_argument(std::string(option) + " requires a number from 1 to " +
                                    std::to_string(maximum));
    return value;
}

void exportCertificate(kunpeng::ITrusteeTlsSessionService& service, const std::string& path)
{
    const auto certificate = service.certificate();
    if (certificate.size() < 2 || certificate.back() != '\0' ||
        std::find(certificate.begin(), certificate.end() - 1, '\0') != certificate.end() - 1)
        throw std::runtime_error("invalid public certificate response");
    FILE* file = std::fopen(path.c_str(), "wb");
    if (file == nullptr)
        throw std::system_error(errno, std::generic_category(), "open certificate file");
    const bool written = std::fwrite(certificate.data(), 1, certificate.size() - 1, file) ==
                         certificate.size() - 1;
    const int closed = std::fclose(file);
    if (!written || closed != 0)
        throw std::runtime_error("write/close certificate file failed");
}
} // namespace

int main(int argc, char** argv)
{
    try {
        static const option options[] = {
            {"port", required_argument, nullptr, 'p'},
            {"certificate-out", required_argument, nullptr, 'c'},
            {"bind", required_argument, nullptr, 'b'},
            {"ta", required_argument, nullptr, 't'},
            {"workers", required_argument, nullptr, 'w'},
            {"max-connections", required_argument, nullptr, 'm'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, 0, nullptr, 0}
        };
        kunpeng::RestAPIHost::Options settings;
        std::string certificatePath;
        std::string taPath;
        int selected;
        while ((selected = getopt_long(argc, argv, "", options, nullptr)) != -1) {
            switch (selected) {
            case 'h': usage(argv[0]); return EXIT_SUCCESS;
            case 'c': certificatePath = optarg; break;
            case 't':
                taPath = optarg;
                if (taPath.empty())
                    throw std::invalid_argument("--ta requires a nonempty path");
                break;
            case 'b': {
                in_addr address{};
                if (inet_pton(AF_INET, optarg, &address) != 1)
                    throw std::invalid_argument("--bind requires an IPv4 address");
                settings.bindAddress = optarg;
                break;
            }
            case 'p': settings.port = static_cast<std::uint16_t>(positiveNumber(optarg, 65535, "--port")); break;
            case 'w': settings.workerCount = positiveNumber(optarg, 32, "--workers"); break;
            case 'm': settings.maxConnections = positiveNumber(optarg, 8, "--max-connections"); break;
            default: usage(argv[0]); return EXIT_FAILURE;
            }
        }
        if (certificatePath.empty() || optind != argc) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        // Every subsequently created thread inherits this blocked signal set.
        sigset_t signals;
        sigemptyset(&signals);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGTERM);
        sigaddset(&signals, SIGUSR1); // Private wakeup for joining the signal waiter.
        const int blocked = pthread_sigmask(SIG_BLOCK, &signals, nullptr);
        if (blocked != 0)
            throw std::system_error(blocked, std::generic_category(), "block shutdown signals");

        kunpeng::ITrusteeTlsSessionService service(taPath);
        exportCertificate(service, certificatePath);
        kunpeng::HostCallDispatcher dispatcher;
        dispatcher.registerHandler(1, [](const kunpeng::HostCallRequest&) {
            const std::string data = "Public demo data from CA.\n";
            return kunpeng::HostCallReply{kunpeng::HostCallStatus::Success,
                {data.begin(), data.end()}};
        });
        settings.hostDispatcher = &dispatcher;
        kunpeng::RestAPIHost host(service, settings);
        std::atomic<int> signalError{0};
        std::thread signalThread([&] {
            int received = 0;
            const int error = sigwait(&signals, &received);
            if (error != 0)
                signalError.store(error);
            if (error != 0 || received != SIGUSR1)
                host.stop();
        });
        std::exception_ptr runError;
        try {
            host.run();
        } catch (...) {
            runError = std::current_exception();
        }
        // run() can fail before listening. Always wake and join the waiter,
        // rather than waiting for an external signal on the failure path.
        const int wakeError = pthread_kill(signalThread.native_handle(), SIGUSR1);
        signalThread.join();
        if (runError)
            std::rethrow_exception(runError);
        if (wakeError != 0)
            throw std::system_error(wakeError, std::generic_category(), "wake signal waiter");
        if (signalError.load() != 0)
            throw std::system_error(signalError.load(), std::generic_category(), "wait for shutdown signal");
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "kunpeng-tls-host: %s\n", error.what());
        return EXIT_FAILURE;
    }
}
