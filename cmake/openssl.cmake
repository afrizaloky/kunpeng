# Build pristine upstream sources, never SGX-patched sources or prebuilt archives.
set(KUNPENG_OPENSSL_ARCHIVE "${PROJECT_SOURCE_DIR}/third_party/openssl-3.5.0.tar.gz" CACHE FILEPATH "Pristine OpenSSL 3.5.0 source tar.gz")
if(NOT EXISTS "${KUNPENG_OPENSSL_ARCHIVE}")
  message(FATAL_ERROR "Set KUNPENG_OPENSSL_ARCHIVE to the local pristine openssl-3.5.0.tar.gz")
endif()
find_package(Perl REQUIRED)
find_program(OPENSSL_MAKE make REQUIRED)
include(ExternalProject)
set(_ossl "${CMAKE_BINARY_DIR}/openssl-ta")
file(MAKE_DIRECTORY "${_ossl}/build/include" "${_ossl}/source/include")
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()
execute_process(COMMAND "${CMAKE_C_COMPILER}" -print-file-name=include
  OUTPUT_VARIABLE _intrinsics OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
set(_libc "${ITRUSTEE_SDK}/thirdparty/open_source/musl/libc")
set(_flags "-nostdinc -isystem ${_intrinsics} -I${_libc} -I${_libc}/arch/aarch64 -I${_libc}/arch/generic -I${ITRUSTEE_SDK}/include/TA -Os -fPIC -mno-outline-atomics -ffunction-sections -fdata-sections -DGETPID_IS_MEANINGLESS -DOPENSSL_NO_SECURE_MEMORY -DOPENSSL_NO_ATEXIT -DAPI_LEVEL=1 -include ${PROJECT_SOURCE_DIR}/ta/openssl_platform.h")
ExternalProject_Add(openssl_ta_build
  URL "${KUNPENG_OPENSSL_ARCHIVE}"
  URL_HASH SHA256=344d0a79f1a9b08029b0744e2cc401a43f9c90acd1044d09a530b4885a8e9fc0
  SOURCE_DIR "${_ossl}/source" BINARY_DIR "${_ossl}/build"
  PATCH_COMMAND ${CMAKE_COMMAND} -DSOURCE=${_ossl}/source -P ${PROJECT_SOURCE_DIR}/cmake/openssl-platform.cmake
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env "CC=${CMAKE_C_COMPILER}" "CFLAGS=${_flags}"
    "${PERL_EXECUTABLE}" "${_ossl}/source/Configure" linux-aarch64
    no-sock no-posix-io no-stdio no-dso no-shared no-threads no-module
    no-tests no-apps no-asm no-async no-secure-memory no-ui-console
    no-engine no-autoload-config no-quic no-dgram no-comp no-zlib
    no-legacy -DNO_SYSLOG --with-rand-seed=none
  BUILD_COMMAND "${OPENSSL_MAKE}" -j4 build_libs
  INSTALL_COMMAND ""
  BUILD_BYPRODUCTS "${_ossl}/build/libssl.a" "${_ossl}/build/libcrypto.a")
foreach(_name SSL Crypto)
  string(TOLOWER "${_name}" _lower)
  add_library(OpenSSL::${_name} STATIC IMPORTED GLOBAL)
  set_target_properties(OpenSSL::${_name} PROPERTIES
    IMPORTED_LOCATION "${_ossl}/build/lib${_lower}.a"
    INTERFACE_INCLUDE_DIRECTORIES "${_ossl}/build/include;${_ossl}/source/include")
  add_dependencies(OpenSSL::${_name} openssl_ta_build)
endforeach()
set_property(TARGET OpenSSL::SSL PROPERTY INTERFACE_LINK_LIBRARIES OpenSSL::Crypto)
