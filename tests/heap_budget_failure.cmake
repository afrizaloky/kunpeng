execute_process(COMMAND "${PROGRAM}" 2 RESULT_VARIABLE result
  OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 2 OR NOT error MATCHES "heap budget exceeded: peak=[0-9]+ limit=1")
  message(FATAL_ERROR "Expected budget rejection (exit 2), got ${result}\n${output}\n${error}")
endif()
message(STATUS "Reduced-budget rejection proven\n${output}\n${error}")
