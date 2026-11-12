#include "ITrusteeTlsSessionService.h"

#include "tee_client_api.h"
#include "tls_protocol.h"

#include <algorithm>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace kunpeng {
namespace {

const TEEC_UUID uuid = TLS_TA_UUID;

std::runtime_error teeError(const char* action, TEEC_Result result,
    std::uint32_t origin)
{
    std::ostringstream message;
    message << action << ": TEEC result=0x" << std::hex << std::setfill('0')
            << std::setw(8) << static_cast<std::uint32_t>(result)
            << " origin=0x" << std::setw(8) << origin;
    return std::runtime_error(message.str());
}

} // namespace

struct ITrusteeTlsSessionService::Impl {
    struct Session {
        explicit Session(Impl& owner) : owner(owner)
        {
            TEEC_Operation operation{};
            operation.started = 1;
            operation.paramTypes = TEEC_PARAM_TYPES(
                TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
            std::uint32_t origin = 0;
            std::lock_guard<std::mutex> lock(owner.contextMutex);
            if (owner.activeSessions >= TLS_MAX_SESSIONS)
                throw std::runtime_error("TLS session capacity reached");
            const auto result = TEEC_OpenSession(&owner.context, &handle,
                &uuid, TEEC_LOGIN_IDENTIFY, nullptr, &operation, &origin);
            if (result != TEEC_SUCCESS)
                throw teeError("open session", result, origin);
            ++owner.activeSessions;
        }

        ~Session() { close(); }

        // Caller holds mutex, or has exclusive ownership during destruction.
        void close()
        {
            if (!closed) {
                std::lock_guard<std::mutex> lock(owner.contextMutex);
                TEEC_CloseSession(&handle);
                --owner.activeSessions;
                closed = true;
            }
        }

        Impl& owner;
        TEEC_Session handle{};
        std::mutex mutex;
        bool closed = false;
    };

    explicit Impl(const std::string& path) : taPath(path)
    {
        if (taPath.find('\0') != std::string::npos)
            throw std::runtime_error("TA path contains NUL");
        const auto result = TEEC_InitializeContext(nullptr, &context);
        if (result != TEEC_SUCCESS)
            throw teeError("initialize context", result, 0);
        context.ta_path = taPath.empty() ? nullptr
            : reinterpret_cast<std::uint8_t*>(taPath.data());
    }

    ~Impl()
    {
        // The host has joined workers before destruction, so no outstanding
        // method may retain a Session referencing this context.
        sessions.clear();
        TEEC_FinalizeContext(&context);
    }

    std::shared_ptr<Session> find(SessionId id)
    {
        std::lock_guard<std::mutex> lock(mapMutex);
        const auto entry = sessions.find(id);
        if (entry == sessions.end())
            throw std::runtime_error("unknown TLS session id");
        return entry->second;
    }

    std::string taPath;
    TEEC_Context context{};
    // Runtime thread safety is unproven: serialize each SDK operation, never
    // socket waits. Session accounting includes temporary certificate sessions.
    std::size_t activeSessions = 0;
    std::mutex contextMutex;
    std::mutex mapMutex;
    std::unordered_map<SessionId, std::shared_ptr<Session>> sessions;
};

ITrusteeTlsSessionService::ITrusteeTlsSessionService(const std::string& taPath)
    : impl_(std::make_unique<Impl>(taPath))
{
}

ITrusteeTlsSessionService::~ITrusteeTlsSessionService() = default;

std::vector<unsigned char> ITrusteeTlsSessionService::certificate()
{
    Impl::Session session(*impl_);
    std::vector<unsigned char> output(TLS_PROTOCOL_CAPACITY);
    TEEC_Operation operation{};
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = output.data();
    operation.params[0].tmpref.size = TLS_PROTOCOL_CAPACITY;
    std::uint32_t origin = 0;
    TEEC_Result result;
    {
        std::lock_guard<std::mutex> lock(impl_->contextMutex);
        result = TEEC_InvokeCommand(&session.handle,
            TLS_CMD_CERTIFICATE, &operation, &origin);
    }
    if (result != TEEC_SUCCESS)
        throw teeError("export certificate", result, origin);
    const auto length = operation.params[0].tmpref.size;
    if (length < 2 || length > output.size() || output[length - 1] != '\0'
        || std::find(output.begin(), output.begin() + length - 1, '\0')
            != output.begin() + length - 1)
        throw std::runtime_error("invalid public certificate response");
    output.resize(length);
    return output;
}

void ITrusteeTlsSessionService::open(SessionId id)
{
    std::lock_guard<std::mutex> lock(impl_->mapMutex);
    if (impl_->sessions.find(id) != impl_->sessions.end())
        throw std::runtime_error("TLS session id already active");
    // Separate allocation keeps SDK session addresses stable as the map grows.
    // Publish only a fully opened session. No map lock spans an invocation.
    impl_->sessions.emplace(id, std::make_shared<Impl::Session>(*impl_));
}

ProcessResult ITrusteeTlsSessionService::process(SessionId id,
    const std::vector<unsigned char>& input)
{
    return invoke(id, input, std::nullopt);
}

ProcessResult ITrusteeTlsSessionService::supplyHostData(SessionId id,
    HostDataRequest request, const std::vector<unsigned char>& data)
{
    if (request.operation != TLS_PROTOCOL_HOST_OP_DEMO_DATA || request.id == 0 ||
        data.empty() || data.size() > TLS_PROTOCOL_HOST_DATA_CAPACITY)
        throw std::runtime_error("invalid host data supply");
    return invoke(id, data, request);
}

ProcessResult ITrusteeTlsSessionService::invoke(SessionId id,
    const std::vector<unsigned char>& input, std::optional<HostDataRequest> request)
{
    auto session = impl_->find(id);
    std::lock_guard<std::mutex> lock(session->mutex);
    if (session->closed)
        throw std::runtime_error("TLS session is closed");
    if (input.size() > TLS_PROTOCOL_CAPACITY)
        throw std::runtime_error("TLS input exceeds protocol capacity");

    ProcessResult response{};
    response.output.resize(TLS_PROTOCOL_CAPACITY);
    unsigned char emptyInput = 0;
    TEEC_Operation operation{};
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_OUTPUT,
        request ? TEEC_VALUE_INOUT : TEEC_VALUE_OUTPUT);
    if (request) {
        operation.params[3].value.a = request->operation;
        operation.params[3].value.b = request->id;
    }
    operation.params[0].tmpref.buffer = input.empty() ? &emptyInput
        : const_cast<unsigned char*>(input.data());
    operation.params[0].tmpref.size = static_cast<std::uint32_t>(input.size());
    operation.params[1].tmpref.buffer = response.output.data();
    operation.params[1].tmpref.size = TLS_PROTOCOL_CAPACITY;
    std::uint32_t origin = 0;
    TEEC_Result result;
    {
        std::lock_guard<std::mutex> sdkLock(impl_->contextMutex);
        result = TEEC_InvokeCommand(&session->handle,
            request ? TLS_CMD_SUPPLY_HOST_DATA : TLS_CMD_PROCESS,
            &operation, &origin);
    }
    if (result != TEEC_SUCCESS)
        throw teeError("process ciphertext", result, origin);

    const auto flags = operation.params[2].value.a;
    const auto length = operation.params[1].tmpref.size;
    constexpr std::uint32_t validFlags = TLS_PROTOCOL_FLAG_HANDSHAKE
        | TLS_PROTOCOL_FLAG_MORE_OUTPUT | TLS_PROTOCOL_FLAG_CLOSED
        | TLS_PROTOCOL_FLAG_FATAL | TLS_PROTOCOL_FLAG_HOST_REQUEST;
    if (length > response.output.size() || operation.params[2].value.b != 0
        || (flags & ~validFlags) != 0)
        throw std::runtime_error("invalid process response");
    const auto op = operation.params[3].value.a;
    const auto requestId = operation.params[3].value.b;
    if (flags & TLS_PROTOCOL_FLAG_HOST_REQUEST) {
        if (op != TLS_PROTOCOL_HOST_OP_DEMO_DATA || requestId == 0 ||
            !(flags & TLS_PROTOCOL_FLAG_HANDSHAKE) ||
            (flags & (TLS_PROTOCOL_FLAG_CLOSED | TLS_PROTOCOL_FLAG_FATAL)))
            throw std::runtime_error("invalid host request response");
        response.hostRequest = HostDataRequest{op, requestId};
    } else if (op != 0 || requestId != 0) {
        throw std::runtime_error("unexpected host request metadata");
    }
    response.output.resize(length);
    response.handshake = (flags & TLS_PROTOCOL_FLAG_HANDSHAKE) != 0;
    response.moreOutput = (flags & TLS_PROTOCOL_FLAG_MORE_OUTPUT) != 0;
    response.closed = (flags & TLS_PROTOCOL_FLAG_CLOSED) != 0;
    response.fatal = (flags & TLS_PROTOCOL_FLAG_FATAL) != 0;
    return response;
}

void ITrusteeTlsSessionService::close(SessionId id)
{
    std::shared_ptr<Impl::Session> session;
    {
        std::lock_guard<std::mutex> lock(impl_->mapMutex);
        const auto entry = impl_->sessions.find(id);
        if (entry == impl_->sessions.end())
            throw std::runtime_error("unknown TLS session id");
        session = entry->second;
        impl_->sessions.erase(entry);
    }
    // An in-flight process retains the allocation. Wait only for that session,
    // then close before returning; a delayed process observes closed instead.
    std::lock_guard<std::mutex> lock(session->mutex);
    session->close();
}

} // namespace kunpeng
