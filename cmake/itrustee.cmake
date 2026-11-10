if(NOT CMAKE_CROSSCOMPILING OR NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
  message(FATAL_ERROR "iTrustee requires -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-itrustee.cmake; native fallback is forbidden")
endif()
execute_process(COMMAND "${CMAKE_C_COMPILER}" -print-file-name=include
  OUTPUT_VARIABLE _compiler_headers OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE _compiler_headers_result)
if(NOT _compiler_headers_result EQUAL 0 OR NOT IS_DIRECTORY "${_compiler_headers}")
  message(FATAL_ERROR "Cannot determine cross compiler intrinsic headers with -print-file-name=include")
endif()
set(_musl "${ITRUSTEE_SDK}/thirdparty/open_source/musl/libc")
set(_script "${ITRUSTEE_SDK}/build/tools/ta_link_64.ld")
foreach(required "${_musl}/stdlib.h" "${_script}" "${ITRUSTEE_SDK}/include/TA/tee_crypto_api.h")
  if(NOT EXISTS "${required}")
    message(FATAL_ERROR "Missing SDK input: ${required}")
  endif()
endforeach()
add_library(itrustee_trusted INTERFACE)
target_compile_definitions(itrustee_trusted INTERFACE API_LEVEL=1)
target_include_directories(itrustee_trusted SYSTEM INTERFACE "${_compiler_headers}")
target_include_directories(itrustee_trusted INTERFACE
  "${_musl}" "${_musl}/arch/aarch64" "${_musl}/arch/aarch64/bits"
  "${_musl}/arch/generic" "${ITRUSTEE_SDK}/include/TA"
  "${ITRUSTEE_SDK}/include/TA/huawei_ext"
  "${ITRUSTEE_SDK}/thirdparty/open_source/libboundscheck/include")
target_compile_options(itrustee_trusted INTERFACE -nostdinc -march=armv8-a -Os
  -fPIC -fno-short-enums -fno-omit-frame-pointer -fstack-protector-strong
  -fno-common -fsigned-char -Wall -Wextra -Werror)
foreach(lib tls_engine mbedtls mbedx509 mbedcrypto everest p256m)
  target_link_libraries(${lib} PRIVATE itrustee_trusted)
endforeach()
add_library(tls_ta SHARED ta/tls_ta.c)
target_link_libraries(tls_ta PRIVATE tls_engine itrustee_trusted)
target_link_options(tls_ta PRIVATE -nostdlib -shared "-Wl,-T,${_script}"
  -Wl,-z,text,-z,now,-z,relro,-z,noexecstack,-z,max-page-size=0x1000,-z,common-page-size=0x1000)
set_target_properties(tls_ta PROPERTIES OUTPUT_NAME combine LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/ta/unsigned")
configure_file(ta/manifest.txt ta/unsigned/manifest.txt COPYONLY)
message(STATUS "TA output: ta/unsigned/libcombine.so (UNSIGNED; not deployable .sec)")
if(KUNPENG_SIGN_TA)
  set(ITRUSTEE_SIGN_PRIVATE_CONFIG "" CACHE FILEPATH "Caller-owned signtool private INI")
  if(NOT EXISTS "${ITRUSTEE_SIGN_PRIVATE_CONFIG}")
    message(FATAL_ERROR "Signing requires ITRUSTEE_SIGN_PRIVATE_CONFIG; no keys are generated or copied")
  endif()
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_custom_target(sign_ta ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/ta/signed"
    COMMAND "${Python3_EXECUTABLE}" -B "${ITRUSTEE_SDK}/build/signtools/signtool_v3.py"
      "${CMAKE_BINARY_DIR}/ta/unsigned" "${CMAKE_BINARY_DIR}/ta/signed"
      --privateCfg "${ITRUSTEE_SIGN_PRIVATE_CONFIG}"
    DEPENDS tls_ta VERBATIM)
endif()
