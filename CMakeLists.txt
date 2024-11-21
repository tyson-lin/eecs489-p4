cmake_minimum_required(VERSION 3.15)
project(StaticRouter)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include(CheckCXXSourceRuns)
include(FetchContent)


FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.14.1
)
FetchContent_MakeAvailable(spdlog)

FetchContent_Declare(
        websocketspp
        GIT_REPOSITORY https://github.com/zaphoyd/websocketpp.git
        GIT_TAG develop
)
FetchContent_MakeAvailable(websocketspp)

message(STATUS "WEBSOCKETPP_INCLUDE: ${websocketpp_SOURCE_DIR}")

add_subdirectory(proto)

file(GLOB_RECURSE SRCS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp")

find_package(Boost REQUIRED COMPONENTS system thread)

add_executable(StaticRouter ${SRCS})
target_link_libraries(StaticRouter proto spdlog::spdlog)
target_include_directories(StaticRouter SYSTEM PRIVATE ${websocketpp_SOURCE_DIR} ${CMAKE_BINARY_DIR}/proto)
target_include_directories(StaticRouter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

CHECK_CXX_SOURCE_RUNS("
    #include <cstdint>

    int main() {
        uint16_t test_value = 0x0100;
        uint8_t *byte_pointer = reinterpret_cast<uint8_t*>(&test_value);
        if (byte_pointer[0] == 0x00) {
            return 0;
        }
        return 1;
    }"
        IS_LITTLE_ENDIAN
)

# Define macro based on the test result
if (IS_LITTLE_ENDIAN)
    add_compile_definitions(__BYTE_ORDER=1)
else()
    add_compile_definitions(__BYTE_ORDER=2)
endif()