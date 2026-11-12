#include "ITrusteeTlsSessionService.h"
#include "tee_client_api.h"
#include "tls_protocol.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <future>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace {
void require(bool condition)
{
    if (!condition) throw std::runtime_error("test assertion failed");
}
template<class F> void rejects(F action)
{
    bool rejected = false;
    try { action(); } catch (const std::runtime_error&) { rejected = true; }
    require(rejected);
}
struct Boundary {
    unsigned active = 0;
    unsigned peak = 0;
    unsigned initialized = 0;
    unsigned finalized = 0;
    unsigned closed = 0;
    unsigned next = 0;
    bool failOpen = false;
    bool failInvoke = false;
    std::uint32_t flags = 15;
    std::uint32_t reserved = 0;
    std::uint32_t length = 3;
    std::vector<unsigned char> cert{'P', 'E', 'M', 0};
    std::mutex mutex;
    std::condition_variable event;
    bool block = false;
    bool entered = false;
    bool release = false;
    std::atomic<unsigned> calls{0};
} boundary;
struct Operation {
    Operation() { require(boundary.calls.fetch_add(1) == 0); }
    ~Operation() { boundary.calls.fetch_sub(1); }
};
void contracts()
{
    kunpeng::ITrusteeTlsSessionService service("/test/ta.sec");
    require(service.certificate() == boundary.cert);
    boundary.cert = {'P', 0, 'M', 0};
    rejects([&] { service.certificate(); });
    boundary.cert = {'P', 'M'};
    rejects([&] { service.certificate(); });
    boundary.cert = {'P', 0};
    boundary.failOpen = true;
    rejects([&] { service.open(1); });
    boundary.failOpen = false;
    service.open(1);
    rejects([&] { service.open(1); });
    auto result = service.process(1, {7, 8});
    require(result.output == std::vector<unsigned char>({1, 2, 3}));
    require(result.handshake && result.moreOutput && result.closed && result.fatal);
    boundary.flags = 16;
    rejects([&] { service.process(1, {}); });
    boundary.flags = 0;
    boundary.reserved = 1;
    rejects([&] { service.process(1, {}); });
    boundary.reserved = 0;
    boundary.length = TLS_PROTOCOL_CAPACITY + 1;
    rejects([&] { service.process(1, {}); });
    boundary.length = 3;
    boundary.failInvoke = true;
    rejects([&] { service.process(1, {}); });
    boundary.failInvoke = false;
    rejects([&] { service.process(1, std::vector<unsigned char>(65537)); });
    service.close(1);
    rejects([&] { service.process(1, {}); });
    rejects([&] { service.close(1); });
    for (unsigned id = 2; id < 1002; ++id) {
        service.open(id);
        service.close(id);
    }
    for (unsigned id = 1002; id < 1010; ++id) service.open(id);
    rejects([&] { service.open(1010); });
    rejects([&] { service.certificate(); });
    service.close(1002);
    service.open(1010);
}
void concurrentClose()
{
    kunpeng::ITrusteeTlsSessionService service("");
    service.open(2000);
    service.open(2001);
    {
        std::lock_guard<std::mutex> lock(boundary.mutex);
        boundary.block = true;
        boundary.entered = false;
        boundary.release = false;
    }
    auto processing = std::async(std::launch::async, [&] { service.process(2000, {}); });
    {
        std::unique_lock<std::mutex> lock(boundary.mutex);
        require(boundary.event.wait_for(lock, std::chrono::seconds(5),
            [] { return boundary.entered; }));
    }
    std::promise<void> closingStarted;
    auto started = closingStarted.get_future();
    auto closing = std::async(std::launch::async, [&] {
        closingStarted.set_value();
        service.close(2000);
    });
    started.get();
    auto other = std::async(std::launch::async, [&] { service.process(2001, {}); });
    {
        std::lock_guard<std::mutex> lock(boundary.mutex);
        boundary.release = true;
        boundary.block = false;
    }
    boundary.event.notify_all();
    require(processing.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    processing.get();
    require(closing.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    closing.get();
    other.get();
    rejects([&] { service.process(2000, {}); });
}
} // namespace

extern "C" {
TEEC_Result TEEC_InitializeContext(const char*, TEEC_Context*)
{
    Operation operation;
    ++boundary.initialized;
    return TEEC_SUCCESS;
}
void TEEC_FinalizeContext(TEEC_Context*)
{
    Operation operation;
    require(boundary.active == 0);
    ++boundary.finalized;
}
TEEC_Result TEEC_OpenSession(TEEC_Context* context, TEEC_Session* session,
    const TEEC_UUID* uuid, uint32_t login, const void* data,
    TEEC_Operation* operation, uint32_t*)
{
    Operation guard;
    require(login == TEEC_LOGIN_IDENTIFY && data == nullptr);
    require(uuid->timeLow == 0xe08f7eca && operation->started == 1);
    if (boundary.failOpen) return TEEC_ERROR_GENERIC;
    session->context = context;
    session->session_id = ++boundary.next;
    ++boundary.active;
    if (boundary.active > boundary.peak) boundary.peak = boundary.active;
    require(boundary.active <= 8);
    return TEEC_SUCCESS;
}
void TEEC_CloseSession(TEEC_Session* session)
{
    Operation guard;
    require(session->session_id != 0 && boundary.active > 0);
    session->session_id = 0;
    --boundary.active;
    ++boundary.closed;
}
TEEC_Result TEEC_InvokeCommand(TEEC_Session* session, uint32_t command,
    TEEC_Operation* operation, uint32_t*)
{
    Operation guard;
    require(session->session_id != 0);
    if (boundary.failInvoke) return TEEC_ERROR_GENERIC;
    if (command == TLS_CMD_CERTIFICATE) {
        require(operation->paramTypes == TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE));
        std::memcpy(operation->params[0].tmpref.buffer,
            boundary.cert.data(), boundary.cert.size());
        operation->params[0].tmpref.size = boundary.cert.size();
    } else {
        require(command == TLS_CMD_PROCESS);
        require(operation->paramTypes == TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_OUTPUT, TEEC_NONE));
        std::unique_lock<std::mutex> lock(boundary.mutex);
        if (boundary.block) {
            boundary.entered = true;
            boundary.event.notify_all();
            require(boundary.event.wait_for(lock, std::chrono::seconds(5),
                [] { return boundary.release; }));
        }
        const unsigned char bytes[]{1, 2, 3};
        std::memcpy(operation->params[1].tmpref.buffer, bytes, sizeof(bytes));
        operation->params[1].tmpref.size = boundary.length;
        operation->params[2].value.a = boundary.flags;
        operation->params[2].value.b = boundary.reserved;
    }
    return TEEC_SUCCESS;
}
}
int main()
{
    try {
        contracts();
        concurrentClose();
        require(boundary.active == 0 && boundary.peak == 8);
        require(boundary.initialized == 2 && boundary.finalized == 2);
        std::cout << "itrustee service tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
