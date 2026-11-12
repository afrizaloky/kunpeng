# CryptoMaterialProvider and iTrustee host-work boundaries

**Research note, 2026-11-12**

This note records source-based findings about kripta-key's `CryptoMaterialProvider`, the native and SGX seams around key material, and possible iTrustee mechanisms for obtaining host-supplied data. The bounded TLS demo described below implements one explicit CA-to-TA host-data continuation. It is not a `CryptoMaterialProvider`, general retrieval integration, or SGX OCALL. No iTrustee device or live Kunpeng runtime validation was performed. The upstream `master` references cited below are mutable; verify the exact source revision and SDK/runtime before relying on them.

## Summary

kripta-key already defines an acquisition-only, synchronous `CryptoMaterialProvider`. It is a C++ interface, not a wire protocol or enclave ABI. Its operations return keys, metadata, time, or random bytes directly to the caller. The non-enclave native implementation forwards to borrowed host-side dependencies. In SGX, the related cache and time paths use explicit OCALL declarations and generated bridge code. That SGX design cannot be assumed portable to iTrustee.

The iTrustee SDK inspected here exposes the ordinary GlobalPlatform client flow, where the Client Application (CA) opens a session and invokes a TA command, and a TA-to-TA invocation API. The bundled public headers do not verify a general synchronous TA-to-CA callback. Upstream iTrustee client headers do expose an agent API, but the agent path is conditional on target driver and authorization policy, and a usable trusted-side API was not verified in the bundled headers. Do not describe it as universally impossible or as a portable OCALL.

**Recommendation:** preserve the provider interface and its synchronous contract by supplying wrapped dependencies to the TA before entering the operation that needs them. If a dependency cannot be known in advance, make the operation an explicit prepare, CA supply, then execute flow. Never wait for unknown host work on the synchronous TA call stack, and never blindly retry a host operation after it may have caused side effects.

## What the provider requires

`../kripta-key/include/kk/kkcs/secure/CryptoMaterialProvider.h:7-26` defines synchronous acquisition methods for `symmetricKey`, `keyPair`, `publicKey`, `keyEncryptionKey`, `metadataEncryptionKey`, `purposeDerivedKey`, `currentTime`, and `randomBytes`. The interface is acquisition-only. Its shared reference lifetime is tied to the operation using it. It does not define serialization, transport, an OCALL, or an enclave ABI.

The native-side adapter at `../kripta-key/kkcs/native/HostAdapters.cpp:103-116` forwards to borrowed `KeyCache`, time, and random dependencies. The production provider at `../kripta-key/kkcs/secure/CryptoMaterialProduction.h:10-53` is a singleton forwarding implementation. These are useful seams to study, but the code's “native” path is not itself proof of an iTrustee design.

The core cache interface at `../kripta-key/include/kk/core/secure/Cache.h:438-443` takes injected synchronous functions for `fetchKey(KeyParameters)`, `fetchPartition(uint32)`, `currentTime()`, and `systemKey(name)`. The first three return `Expect` values for wrapped key/partition bridges or time. `systemKey` returns an array and is not evidence of a design that fetches plaintext system keys from an untrusted host.

In SGX, `../kripta-key/common/cache/secure/Cache.cpp:88-106` performs a key OCALL and deserializes its result, while `:153-174` wires the SGX cache. Certificate validation appears at `:119-150`. The declarations are in `../kripta-key/include/kk/Cache.edl:8-22`; transport status and application error are separated in `../kripta-key/include/kk/core/secure/SGXOcall.h:24-35,69-111`. Generated SGX bridge handles and re-entry semantics are SGX-specific, not portable interfaces.

The cache's unwrap, identity, type, and integrity checks are visible in `../kripta-key/include/kk/core/secure/Cache.h:196-282`. Partition unwrapping is in `../kripta-key/common/cache/secure/Cache.cpp:280-327`. A cache refresh can retain a prior key after a fetch failure. Any integration must understand and preserve that policy rather than accidentally replacing it with a retry or fallback policy.

Expiry and revocation are caller-side concerns for purpose-derived material, as shown in `../kripta-key/kkcs/secure/CryptoMaterialPrivate.h:27-83`. The broader SDK also has other enclave call surfaces: KKA's auditor calls in `../kripta-key/include/kk/securememory/AuditorEnclaveOCall.edl:1-8` and additional KKCS calls in `../kripta-key/include/kk/securememory/CryptoServiceEnclave.edl:41-86`. Those separate interfaces do not establish a general callback mechanism for this provider.

## The synchronous stack constraint

A method on `CryptoMaterialProvider` returns a value or error before its caller proceeds. The provider interface does not offer a future, continuation token, or “suspend and re-enter” contract. A TA-side implementation that tried to obtain an unknown value by waiting for its CA to call back would need a re-entrant or agent mechanism supported by the actual platform. Ordinary `TEEC_InvokeCommand` does not provide that property in the bundled SDK flow.

This matters for lock and worker ownership as well as interface shape. Do not hold a TA lock while waiting for a CA. On the host, keep the event loop nonblocking and run backend work on workers. This does not mean no thread may ever block: backend workers can block on a supported operation. An independently available agent worker can also matter to avoid deadlocking an agent request against the worker that must service it.

## iTrustee mechanisms observed

### Ordinary CA command flow

The bundled CA API at `third_party/itrustee_sdk/include/CA/tee_client_api.h:84-121` exposes `TEEC_OpenSession` and `TEEC_InvokeCommand`. The corresponding TA API at `third_party/itrustee_sdk/include/TA/tee_core_api.h:32-73` includes TA-to-TA invocation, not a general host callback. The ordinary exposed command flow is CA-driven: the CA enters a TA command and receives its result when that command returns. This description excludes conditional platform agent paths; it is not a claim that every possible iTrustee interaction is CA-driven.

A common-TEE API should not be confused with arbitrary callbacks. In particular, `TEEC_LOGIN_IDENTIFY` caller identity data is a fixed session-open facility handled by this application's `TA_OpenSessionEntryPoint`, not a general TA-to-host work request.

### Native agent path

The upstream iTrustee client header `itrustee_client/include/tee_client_ext_api.h` in `https://github.com/openeuler-mirror/itrustee_client/blob/master/include/tee_client_ext_api.h` declares these host-side signatures:

```c
TEEC_Result TEEC_EXT_RegisterAgent(uint32_t agentId, int *devFd, void **buffer);
TEEC_Result TEEC_EXT_WaitEvent(uint32_t agentId, int devFd);
TEEC_Result TEEC_EXT_SendEventResponse(uint32_t agentId, int devFd);
TEEC_Result TEEC_EXT_UnregisterAgent(uint32_t agentId, int devFd, void **buffer);
```

The header describes a shared buffer and a blocking `WaitEvent`. Its buffer-size comment applies to that interface version, not every platform version. The upstream driver source `itrustee_tzdriver/core/agent.c` at `https://github.com/openeuler-mirror/itrustee_tzdriver/blob/master/core/agent.c` shows an agent work path that wakes a helper and waits for its response. The agent allowlist hook `is_allowed_agent_ca` is weak and defaults to `-EFAULT`; authorization depends on target policy and identity. Driver buffer thresholds also vary by platform, including a CCOS-specific threshold, so do not generalize one size across releases.

The bundled SDK does not include `tee_client_ext_api.h`, and no trusted-side custom-agent API was verified in its TA headers. Constants such as `TEE_RETURN_AGENT_BUFFER` are not, by themselves, callable APIs. This evidence does not prove a custom trusted-side agent API is impossible, private on every platform, or absent from every SDK variant. Its availability and contract remain unverified for this target.

Huawei documentation supports the platform-specific nature of deployment and policy. The 24.0.0 deployment guide describes `.sec` signing and placement under `/var/itrustee/ta`, with caller authorization configured through `addcaller_ca_exec`: [English deployment guide](https://support.huawei.com/enterprise/en/doc/EDOC1100433026/ac41e320/establishing-a-connection), [Chinese deployment guide](https://support.huawei.com/enterprise/zh/doc/EDOC1100433031/a293bf95). The attestation API reference is feature-specific, not evidence of a generic callback: [API reference](https://support.huawei.com/enterprise/en/doc/EDOC1100433033/f9d418d9/apis). Some direct Huawei retrievals returned 403; those references should be checked against the documentation package for the deployed SDK. This note does not assert the agent path is available on this repository's target.

## Recommended integration shape

### Ownership and recommended integration shape

Keep `CryptoMaterialProvider` as the existing synchronous acquisition interface. Inject a TA-owned cache/provider into it, analogous to the native provider's injected dependencies; do not add a generic compatibility framework or turn the provider into a wire protocol. Keep SGX OCALL transport and generated bridge behavior backend-specific. An iTrustee implementation should adapt its own command or, only where verified and authorized, agent transport to the same trusted provider/cache boundary.

```text
Linux CA
  sockets + nonblocking event loop
  fixed worker pool for backend and TA calls
        | encrypted TLS records / bounded commands
        v
      iTrustee TA ------------------------+
        | TLS, authentication, request    |
        | parsing, authorization,         |
        | preparation and execution       |
        |                                 |
        +--> TA-owned CryptoMaterialProvider
               +--> TA-owned wrapped-material cache
               +--> TEE_GenerateRandom
               +--> explicitly validated time source
                         ^
                         | wrapped records only, for exact TA requests
        Linux repositories / KKM/KKCS service
```

TLS remains inside the TA. The TA decrypts and parses the TLS request, authenticates and authorizes the principal, and derives the exact key, partition, KEK, metadata, and other dependencies needed for that operation. The CA is a transport and retrieval broker: it fetches wrapped records for those requested selectors and returns them, but does not choose trusted operations or decide what the TA should execute. It may pre-supply candidate wrapped records to reduce round trips; the TA must validate every record and accept only dependencies derived from the authorized request. Key selectors and dependency names can reveal sensitive metadata even when values remain wrapped, so minimize and bound what crosses the boundary, avoid logging selectors, and protect transport and shared buffers.

The diagram is a trust and ownership recommendation, not a claim that these exact modules or interfaces exist. Existing provider methods remain the mapping point: key, key-pair, public-key, KEK, metadata-key and purpose-derived-key acquisition uses TA cache entries backed by validated wrapped material; `currentTime` uses a specifically validated clock; `randomBytes` uses trusted randomness. Never fetch plaintext host `systemKey` values. Inject the existing system-key function only when its implementation and storage are TA-owned and trusted. The existing interfaces and cited cache behavior remain the evidence for this mapping, not a promise that every operation can be serviced by one generic retrieval endpoint. The implemented `DEMO_DATA` continuation is separate: it returns fixed public response content and does not supply key material or establish integrity, authenticity, freshness, or authorization.

### Preparation and execution protocol

When a dependency is missing, use explicit **PREPARING -> READY -> EXECUTING -> COMPLETED** states, with **FAILED** and cleanup paths. These are protocol concepts, not iTrustee SDK APIs. Preparation must be an operation-specific, bounded preflight: identify nested dependencies such as key -> partition -> KEK/system keys, and any refresh-required dependencies, without performing business side effects. It may populate the trusted cache with validated material. Do not use `KEY_NOT_FOUND` to mean “pending.” If all material is ready, keep a single-command fast path; add host round trips only for unresolved dependencies.

Bind preparation to an opaque TA handle, TA session, authenticated principal, exact request selectors and parameters. Subsequent supply and execute commands must match that binding exactly. Reject request substitution, stale or duplicate supplies, malformed data and out-of-order transitions. Do not let a CA-supplied selector redefine the authorized request. Bound handle lifetime, outstanding preparations, response sizes, rounds and total work; clean up on failure, expiry, session close and TA teardown.

The execution gate checks that dependencies are stable and pinned for the operation, then rechecks relevant authorization and revocation state. Never hold a TA lock across a host wait. If material is still missing, return a controlled failure or a clearly defined preparation-needed result and require an explicit protocol transition; do not treat a cache miss as a reason to block the synchronous provider call. Once side effects may have started, a lost result leaves the outcome uncertain. Do not blindly retry; report or reconcile the uncertain outcome according to the operation's semantics.

A custom agent is a possible transport only if the deployed TA API is documented and verified and the target's authorization policy permits it. It is a practical option only when the operation has a necessary data-dependent retrieval or measurement requirement that cannot be met by pre-supply. Give agent servicing an independently available worker so it cannot deadlock against a worker waiting for the request. Apply the same principal, selector, wrapped-record and state-transition validation as the command path. This conditional path is not a portable OCALL or a general callback guarantee.

The current TLS command ABI retains `PROCESS=1` and `CERTIFICATE=2`, and adds `TLS_CMD_SUPPLY_HOST_DATA=3` for the bounded public-data demo. For a bodyless `POST /` with exactly one zero `Content-Length`, the TA parses the HTTP request and sends a `HOST_REQUEST` with operation `DEMO_DATA` and a request ID. The CA responds through command 3 with the fixed public demo data `Public demo data from CA.\n`. Only operation/ID metadata travels from TA to CA, never plaintext HTTP. The TA copies the supplied data and accepts only 1 to 128 printable ASCII bytes or LF; CR, NUL and other controls are rejected, as are replayed operation/ID pairs. It constructs the bounded HTTP response and encrypts it with TLS. One request may be pending per connection; one worker invocation dispatches at most one host request, with no recursive host requests.

This is an explicit continuation in the application protocol: the TA returns a host-work request, the CA supplies data in a later command, and the TA resumes TLS response processing. It does not suspend and resume an SGX enclave stack, add SGX re-entry, or provide a real SGX OCALL. The fixed demo data is untrusted response content, not an authenticated key record, and authorization must not rely on it. There is no general host-work preparation/resume protocol for key acquisition, arbitrary filesystem or network access, or request-body forwarding. That broader preparation/execution proposal remains unimplemented. Existing GET behavior, including keep-alive and explicit close, and the eight-session limit are unchanged.

### Validation, freshness, and side effects

Separate transport status from application status. SGX's status-plus-application-error pattern is a conceptual reference only; do not copy its generated ABI as an iTrustee API. Bound and validate all copied input lengths, types, identities, integrity, cryptographic-key-use purpose, expiry and revocation at the trusted boundary. Copy host data into TA-owned memory before use, do not retain host pointers, and define buffer ownership, mutation, lifetime and clearing. Do not expose plaintext keys, decrypted objects or new secret-bearing outputs through the CA or shared agent memory. TLS responses remain TA-encrypted, except for plaintext already authorized by the existing application protocol; this design adds no secret exposure.

Treat freshness separately from integrity. Authenticated versions and revocation epochs need a trustworthy baseline; enforcing rollback resistance across restart also requires suitable rollback-resistant persistence. A host-provided timestamp is untrusted unless authenticated by a defined source. The existing cache's stale-on-refresh-failure behavior must be an explicit policy choice, and must never bypass known revoked or expired state. Fail closed when a required freshness decision cannot be made under that policy.

Use `TEE_GenerateRandom(void *, size_t)` as the trusted RNG mapping, as declared in `third_party/itrustee_sdk/include/TA/tee_crypto_api.h:552`; the declaration alone does not establish target RNG quality. For `currentTime`, explicitly validate the selected source, epoch, units (including milliseconds where required), monotonicity and trust on the deployed target. RTC and system-time declarations, including a REE time source, are not automatically an authenticated epoch clock.

KKA and KKM have different side effects and trust requirements. Do not force them into one universal OCALL or retrieval flow. Define operation-specific preparation, authorization, freshness and completion semantics for each use. Preserve idempotency only when the operation supports it, and distinguish transport failure from application failure and uncertain completion.

## Proposed bounded CA-data framework

This is a standalone design proposal for operations that need dynamically retrieved CA data, such as wrapped records fetched by the Client Application (CA), up to 1 MiB. It is not implemented by the fixed 128-byte `DEMO_DATA` continuation, and it does not change the current command ABI. In particular, it does not repurpose command 3 or claim compatibility with an existing CA or TA. A future implementation requires a coordinated CA and TA upgrade and a deliberate transport mapping.

### Operations and continuation binding

Define a closed set of typed semantic operation IDs, each dispatched by a CA allowlist to a specific retrieval handler and data format. The TA requests an operation, not a function name, path, URL, shell command, or other host-selected action. Unknown IDs fail closed. The operation definition also states its object-size limit, permitted empty-object behavior, chunk rules, decoder, and any operation-specific validation.

The TA initiates a request using a retained operation and session binding and a nonreused request ID. Keep at most one request pending per session. Every subsequent chunk must match that session, request ID, and operation. Reject mismatches, replay, out-of-order delivery, and bytes received after a final chunk. IDs must not be reused during the lifetime in which stale responses could be presented. This is an explicit continuation: return from the current command and later accept a matching supply command. It does not suspend or resume a TA stack. Never hold a TA lock while waiting for host work.

Keep `CryptoMaterialProvider` synchronous and acquisition-only. Before entering the operation that uses it, prepare and validate the required material in TA-owned state, then provide the synchronous provider with that prepared material. If a dependency is missing, use the explicit prepare, CA supply, validate, and execute flow. Do not make a provider method block on the CA or convert a cache miss into an implicit callback.

### Logical wire contract

The framework's logical request contains an operation ID, request ID, and bounded operation arguments. A chunk reply contains the request ID, status, offset, final flag, and payload. Session and operation are bound by the pending TA request and checked alongside each reply. Transport status and application status remain distinct.

Specify a fixed-width, versioned schema with explicit byte order, field lengths, and validation rules. Do not serialize raw C or C++ structure layouts. Validate the version, enum values, encoded lengths, arithmetic, and exact message boundaries before use. The schema describes a logical contract only; it assigns no new iTrustee command IDs and does not promise an existing transport can carry it unchanged.

### Object and command bounds

The maximum logical object size is 1 MiB, exactly 1,048,576 bytes. The existing command input and output cap is 64 KiB, exactly 65,536 bytes, and includes the command envelope. Therefore each chunk payload must be no larger than 65,536 bytes minus the encoded envelope size. A 1 MiB object cannot fit in one existing-size command.

A final chunk may reveal the actual object length; the TA must not require a trusted total length in advance. An optional total-length hint is untrusted metadata, not an allocation authority. Enforce each append with checked subtraction: first establish that the current length is at most the object cap, then require the incoming length to be at most the cap minus the current length. Validate the chunk offset against the expected next offset before copying. Reject any chunk whose encoded command exceeds the command cap or whose payload exceeds the remaining object capacity.

Use bounded chunk counts and per-operation limits so tiny chunks cannot cause unbounded command work. One proposed starting policy is a 16 KiB minimum for nonfinal payloads, a 65-chunk maximum per object, and an operation-specific override only when justified. These are design values, not platform guarantees. The count allows 64 nonfinal 16 KiB chunks followed by an empty final terminator at exactly 1 MiB. Reject smaller nonfinal chunks explicitly; handlers must coalesce upstream fragments into permitted chunks. Bound request, abort, and other control commands separately so the chunk limit cannot be bypassed with unlimited control traffic. Document that tradeoff and fail explicitly when the configured count is exceeded rather than silently truncating or retrying.

### Acceptance state and errors

Track each request through `Awaiting`, `Receiving`, `Complete`, `Consumed`, or `Failed`. Only `Awaiting` or `Receiving` may accept the next matching chunk. A valid final chunk moves the object to `Complete`; only operation-specific trusted validation can make it usable. After use, mark it `Consumed`. Any framing, identity, offset, size, ordering, decode, integrity, freshness, or host error moves it to `Failed`; no partial object from a failed request may be used.

Reject zero-length nonfinal chunks. An empty final chunk may represent an empty object only if that operation permits one. It may also terminate a nonempty object exactly at the 1 MiB boundary when the previous chunk ended at that offset without being marked final. After any final chunk, reject all further bytes for that request. A terminal host error fails the request and discards partial data; it must not be converted into partial success.

### Memory admission and buffering

Buffer in TA-owned memory with a hard object cap. Do not preallocate 1 MiB for every session. Reserve capacity before allocation or growth, and enforce both per-object and aggregate budgets. One proposed initial budget is 2 MiB of payload buffering across at most eight sessions, excluding the existing TLS and metadata baseline. Admission must account for the requested growth before copying; if capacity is unavailable, fail or defer according to an explicit bounded policy. Never automatically grow the TA heap, and do not treat these example budgets as proof that the target's configured heap can support them.

Keep a clear owner for each buffer, bound its lifetime to the retained request, and clear or release it on consumption, failure, abort, session close, and TA teardown. Check the actual final length before decoding. Streaming may reduce buffering only for operations whose semantics allow it. It must not make material available to the application before the complete object has passed its required authentication and validation.

### Trust and operation-specific validation

CA data is untrusted. Correlation with a pending ID does not establish authenticity, integrity, freshness, or authorization. Copy bytes into TA-owned memory before validation or use, never retain host pointers, and avoid time-of-check/time-of-use gaps by validating the exact owned bytes later consumed. The TA owns operation policy and selectors. Host data must not determine authorization, an HTTP request selector, a filesystem path, a function to call, or a shell action. Do not send plaintext secrets or decrypted key material to the CA.

Decode and validate records inside the TA according to their operation. For cryptographic material, check the expected record type, identity, integrity, purpose, expiry, revocation, and authenticated version or freshness policy before adding it to a trusted cache. A transport success is not an application success. If a host operation may have caused side effects and its result is lost, completion is uncertain; do not automatically replay it. Define abort and teardown behavior without assuming that a host timeout cancels work already entered into the TEE or proves trusted time has elapsed.

### Host scheduling and HTTP boundary

Keep the CA event loop nonblocking. Dispatch retrieval through bounded workers and bounded transfer work so a large object or many small chunks cannot monopolize the host. Apply explicit per-request deadlines and cleanup, while treating host-side timeout as a host policy only: it does not prove trusted-time expiry and cannot cancel an already-entered TEE command. Teardown, aborts, transport errors, and uncertain side effects must have explicit outcomes, with no automatic replay unless the operation is known to be idempotent.

A 1 MiB HTTP content object cannot fit in one existing 64 KiB ciphertext command output; the host's separate outbound queue limit also does not establish support for a whole 1 MiB response. This framework does not promise HTTP streaming. Supporting a large HTTP response would separately require a bounded TLS output pump and correct `Content-Length` or HTTP chunked-transfer framing. Binary transport can carry arbitrary bytes within its bounds; each operation's handler must still enforce its own format policy. The demo's printable-ASCII restriction remains demo-specific and is not a general binary-transport rule.

### Acceptance tests and migration

A future implementation should test object sizes 0, 1, the maximum payload for one 64 KiB envelope, exactly 65,536 bytes, exactly 1 MiB, and one byte over 1 MiB. Include maximum-envelope accounting, 1 MiB termination by a final zero-length chunk where permitted, one-byte-over rejection, tiny-chunk count limits, aggregate-budget admission and release, offset gaps and overlaps, wrong session/ID/operation, replay, bytes after final, terminal host error after partial data, malformed lengths and versions, abort and session-close cleanup, dynamic final length without a trusted hint, and operation-specific partial-authentication rejection. Test network GET behavior separately, including bounded TLS output and HTTP framing if large response support is added.

Migration should proceed in explicit stages: first isolate the fixed demo handler from the general protocol, then implement and test the versioned bounded chunk contract, then add operation-specific decoders and cache integration for KKCS. Confirm the deployed iTrustee transport, command ABI, heap budget, authorization policy, and cancellation behavior before selecting platform bindings. No framework code or target validation is claimed here.

## Evidence index

Repository paths in the first column are relative to the sibling kripta-key checkout (`../kripta-key` from this repository root, or `../../kripta-key` in Markdown links from `docs`). Ranges refer to the cited source lines. Upstream links point to mutable `master` and should be pinned to the deployed revision for a reproducible review.

| Finding | Source |
|---|---|
| Provider API, synchronous acquisition methods and lifetime | [`../../kripta-key/include/kk/kkcs/secure/CryptoMaterialProvider.h`](../../kripta-key/include/kk/kkcs/secure/CryptoMaterialProvider.h), lines 7-26 |
| Native forwarding adapter | [`../../kripta-key/kkcs/native/HostAdapters.cpp`](../../kripta-key/kkcs/native/HostAdapters.cpp), lines 103-116 |
| Production singleton provider | [`../../kripta-key/kkcs/secure/CryptoMaterialProduction.h`](../../kripta-key/kkcs/secure/CryptoMaterialProduction.h), lines 10-53 |
| Injected cache fetch, time and system-key functions | [`../../kripta-key/include/kk/core/secure/Cache.h`](../../kripta-key/include/kk/core/secure/Cache.h), lines 438-443 |
| SGX fetch/deserialization, certificate validation and wiring | [`../../kripta-key/common/cache/secure/Cache.cpp`](../../kripta-key/common/cache/secure/Cache.cpp), lines 88-106, 119-174 |
| SGX OCALL declarations and status/error distinction | [`../../kripta-key/include/kk/Cache.edl`](../../kripta-key/include/kk/Cache.edl), lines 8-22; [`../../kripta-key/include/kk/core/secure/SGXOcall.h`](../../kripta-key/include/kk/core/secure/SGXOcall.h), lines 24-35, 69-111 |
| Cache unwrap, identity, type, integrity and refresh behavior | [`../../kripta-key/include/kk/core/secure/Cache.h`](../../kripta-key/include/kk/core/secure/Cache.h), lines 196-282 |
| Partition unwrap | [`../../kripta-key/common/cache/secure/Cache.cpp`](../../kripta-key/common/cache/secure/Cache.cpp), lines 280-327 |
| Purpose expiry and revocation responsibility | [`../../kripta-key/kkcs/secure/CryptoMaterialPrivate.h`](../../kripta-key/kkcs/secure/CryptoMaterialPrivate.h), lines 27-83 |
| Additional enclave call surfaces, not general provider callbacks | [`../../kripta-key/include/kk/securememory/AuditorEnclaveOCall.edl`](../../kripta-key/include/kk/securememory/AuditorEnclaveOCall.edl), lines 1-8; [`../../kripta-key/include/kk/securememory/CryptoServiceEnclave.edl`](../../kripta-key/include/kk/securememory/CryptoServiceEnclave.edl), lines 41-86 |
| Bundled iTrustee CA session and invocation API | `third_party/itrustee_sdk/include/CA/tee_client_api.h`, lines 84-121 |
| Bundled TA-to-TA API | `third_party/itrustee_sdk/include/TA/tee_core_api.h`, lines 32-73 |
| Bundled TA random API | `third_party/itrustee_sdk/include/TA/tee_crypto_api.h`, line 552 |
| Bundled TA clock API declarations | `third_party/itrustee_sdk/include/TA/tee_time_api.h`, lines 25, 33, 77 |
| Bundled TA trusted-storage object APIs | `third_party/itrustee_sdk/include/TA/tee_trusted_storage_api.h`, lines 129-165; deployment guarantees still require target validation |
| Current TLS commands and bounded demo continuation | `include/tls_protocol.h`, `PROCESS=1`, `CERTIFICATE=2`, `TLS_CMD_SUPPLY_HOST_DATA=3`; this application command exchange is not a stack-preserving OCALL |
| Upstream iTrustee client agent declarations | [openeuler-mirror/itrustee_client `tee_client_ext_api.h`](https://github.com/openeuler-mirror/itrustee_client/blob/master/include/tee_client_ext_api.h), mutable `master` |
| Agent work, authorization hook and platform-specific buffer thresholds | [openeuler-mirror/itrustee_tzdriver `agent.c`](https://github.com/openeuler-mirror/itrustee_tzdriver/blob/master/core/agent.c), mutable `master` |
| Huawei deployment and feature-specific attestation references | [English deployment guide](https://support.huawei.com/enterprise/en/doc/EDOC1100433026/ac41e320/establishing-a-connection), [Chinese deployment guide](https://support.huawei.com/enterprise/zh/doc/EDOC1100433031/a293bf95), [API reference](https://support.huawei.com/enterprise/en/doc/EDOC1100433033/f9d418d9/apis) |

## Scope and limitations

This note is based on source inspection and the references listed above. The bounded `DEMO_DATA` command is an implemented application-level continuation for public response data only; it does not demonstrate a stack-preserving OCALL, a trusted-side agent call, configured agent authorization, or a general provider/retrieval protocol. The broader preparation/execution design remains a recommendation, not an implementation, and this is not a full KKA, KKM, or KKCS port. TA time, RNG, persistent storage, signing, deployment policy, and the host-data path have not been validated on an iTrustee device or live Kunpeng runtime. Because command 3 changes the CA/TA `PROCESS` slot-3 metadata ABI, rebuild the CA and TA together, sign the resulting TA, and redeploy it as a matched pair. No backward compatibility with an older CA or TA is provided. These documents make no deployment-validation claim.
