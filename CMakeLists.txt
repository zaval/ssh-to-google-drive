cmake_minimum_required(VERSION 3.28)
project(ssh_to_gdrive)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)
FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/libcpr/cpr.git
        GIT_TAG 1.12.0
        CMAKE_ARGS "-DWITH_LIBPSL=OFF"
)

set(CPR_USE_SYSTEM_LIB_PSL ON)
FetchContent_MakeAvailable(cpr)

#FetchContent_Declare(json
#        URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
#)
#FetchContent_MakeAvailable(json)

FetchContent_Declare(jwt-cpp
        GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
        GIT_TAG v0.7.0
)
FetchContent_MakeAvailable(jwt-cpp)

FetchContent_Declare(spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.15.3
)
FetchContent_MakeAvailable(spdlog)

find_package(OpenSSL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSSH REQUIRED libssh)

include_directories(${LIBSSH_INCLUDE_DIRS})
link_directories(${LIBSSH_LIBRARY_DIRS})
add_definitions(${LIBSSH_CFLAGS_OTHER})

add_executable(ssh_to_gdrive main.cpp
        gdriveapi.cpp
        gdriveapi.h
        argparser.cpp
        argparser.h
        md5.cpp
        md5.h
        sftpclient.cpp
        sftpclient.h)

find_package(Threads REQUIRED)

target_link_libraries(ssh_to_gdrive PRIVATE
        ${LIBSSH_LIBRARIES}
        cpr::cpr
        nlohmann_json::nlohmann_json
        jwt-cpp::jwt-cpp
        OpenSSL::Crypto
        spdlog
        Threads::Threads
)



#if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
#    target_compile_options(ssh_to_gdrive PRIVATE -Wno-deprecated-declarations)
#endif ()


set_target_properties(ssh_to_gdrive PROPERTIES
        INSTALL_RPATH "$ORIGIN/../lib"
)


install(TARGETS ssh_to_gdrive cpr spdlog
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)


