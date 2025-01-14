set(TEST_SOURCES
    GDBTest.cc
)

add_executable(gdbtests ${TEST_SOURCES})

target_include_directories(gdbtests PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(gdbtests PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_link_libraries(gdbtests libsimeng)
target_link_libraries(gdbtests gmock_main)
target_compile_options(gdbtests PRIVATE ${SIMENG_COMPILE_OPTIONS})

add_test(NAME gdb_tests COMMAND gdbtests)

if (SIMENG_ENABLE_GDB)
    target_compile_definitions(gdbtests PUBLIC -DGDB_ENABLED)
endif()
