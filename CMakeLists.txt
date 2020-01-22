cmake_minimum_required (VERSION 3.7)
project (libjuice
	DESCRIPTION "JUICE is an UDP-only ICE library"
	VERSION 0.2.0
	LANGUAGES C)

option(USE_NETTLE "Use Nettle instead of OpenSSL for HMAC computation" OFF)

set(C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/Modules)

set(LIBJUICE_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/src/addr.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/agent.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/crc32.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/hmac.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/ice.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/juice.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/log.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/random.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/stun.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/udp.c
)

set(TESTS_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/test/main.c
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_library(juice SHARED ${LIBJUICE_SOURCES})
set_target_properties(juice PROPERTIES VERSION ${PROJECT_VERSION})

target_include_directories(juice PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(juice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)
target_include_directories(juice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(juice Threads::Threads)

add_library(juice-static STATIC EXCLUDE_FROM_ALL ${LIBJUICE_SOURCES})
set_target_properties(juice-static PROPERTIES VERSION ${PROJECT_VERSION})

target_include_directories(juice-static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(juice-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)
target_include_directories(juice-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(juice-static Threads::Threads)

if (USE_NETTLE)
	find_package(Nettle REQUIRED)
    target_compile_definitions(juice PRIVATE USE_NETTLE=1)
    target_link_libraries(juice Nettle::Nettle)
    target_compile_definitions(juice-static PRIVATE USE_NETTLE=1)
    target_link_libraries(juice-static Nettle::Nettle)
else()
    find_package(OpenSSL REQUIRED)
    target_compile_definitions(juice PRIVATE USE_NETTLE=0)
    target_link_libraries(juice OpenSSL::SSL)
    target_compile_definitions(juice-static PRIVATE USE_NETTLE=0)
    target_link_libraries(juice-static OpenSSL::SSL)
endif()

add_library(LibJuice::LibJuice ALIAS juice)
add_library(LibJuice::LibJuiceStatic ALIAS juice-static)

# Main Test
add_executable(juice-tests ${TESTS_SOURCES})
target_include_directories(juice-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
set_target_properties(juice-tests PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(juice-tests PROPERTIES OUTPUT_NAME tests)
target_link_libraries(juice-tests juice)

