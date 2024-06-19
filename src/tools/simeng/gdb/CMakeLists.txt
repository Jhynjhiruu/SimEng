target_sources(simeng PUBLIC GDBStub.cc tinyxml2.cpp)

target_compile_definitions(simeng PUBLIC -DGDB_ENABLED)