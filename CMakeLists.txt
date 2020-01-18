cmake_minimum_required (VERSION 3.7)
project (libjuice
	DESCRIPTION "JUICE is an UDP-only ICE library"
	VERSION 0.0.1
	LANGUAGES C)

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
find_package(Nettle REQUIRED)

add_library(juice SHARED ${LIBJUICE_SOURCES})
set_target_properties(juice PROPERTIES VERSION ${PROJECT_VERSION})

target_include_directories(juice PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(juice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)
target_include_directories(juice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(juice
						Threads::Threads
						Nettle::Nettle
						)

add_library(juice-static STATIC EXCLUDE_FROM_ALL ${LIBJUICE_SOURCES})
set_target_properties(juice-static PROPERTIES
	VERSION ${PROJECT_VERSION}
	CXX_STANDARD 17)

target_include_directories(juice-static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(juice-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)
target_include_directories(juice-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(juice-static
						Threads::Threads
						Nettle::Nettle
						)

add_library(LibJuice::LibJuice ALIAS juice)
add_library(LibJuice::LibJuiceStatic ALIAS juice-static)

# Main Test
add_executable(juice-tests ${TESTS_SOURCES})
set_target_properties(juice-tests PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(juice-tests PROPERTIES OUTPUT_NAME tests)
target_link_libraries(juice-tests juice)

