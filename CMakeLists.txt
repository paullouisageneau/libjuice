cmake_minimum_required (VERSION 3.7)
project (libjuice
	VERSION 0.7.4
	LANGUAGES C)
set(PROJECT_DESCRIPTION "JUICE is a UDP ICE library")

option(USE_NETTLE "Use Nettle for hash functions" OFF)
option(NO_SERVER "Disable server support" OFF)
option(NO_TESTS "Disable tests build" OFF)
option(WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

# Mitigations
option(ENABLE_LOCALHOST_ADDRESS "List locahost addresses in candidates" OFF)
option(ENABLE_LOCAL_ADDRESS_TRANSLATION "Translate local addresses to localhost" OFF)

if(MSVC)
	option(NO_ATOMICS "Force disabling C11 atomics" ON)
else()
	option(NO_ATOMICS "Force disabling C11 atomics" OFF)
endif()

set(C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/Modules)

if(WIN32)
	add_definitions(-DWIN32_LEAN_AND_MEAN)
	if (MSVC)
		add_definitions(-DNOMINMAX)
		add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	endif()
endif()

set(LIBJUICE_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/src/addr.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/agent.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/crc32.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/const_time.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/base64.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/hash.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/hmac.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/ice.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/juice.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/log.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/random.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/server.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/stun.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/timestamp.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/turn.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/udp.c
)

set(LIBJUICE_HEADERS
	${CMAKE_CURRENT_SOURCE_DIR}/include/juice/juice.h
)

set(TESTS_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/test/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/crc32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/stun.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/gathering.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/connectivity.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/notrickle.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/turn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/server.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/conflict.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/bind.c
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_library(juice SHARED ${LIBJUICE_SOURCES})
set_target_properties(juice PROPERTIES VERSION ${PROJECT_VERSION})

target_include_directories(juice PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(juice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)
target_include_directories(juice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(juice PUBLIC Threads::Threads)

add_library(juice-static STATIC EXCLUDE_FROM_ALL ${LIBJUICE_SOURCES})
set_target_properties(juice-static PROPERTIES VERSION ${PROJECT_VERSION})

target_include_directories(juice-static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(juice-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)
target_include_directories(juice-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(juice-static PUBLIC Threads::Threads)

if(WIN32)
	target_link_libraries(juice PRIVATE
		ws2_32 # winsock2
		bcrypt)
	target_link_libraries(juice-static PRIVATE
		ws2_32 # winsock2
		bcrypt)
endif()

if (USE_NETTLE)
	find_package(Nettle REQUIRED)
    target_compile_definitions(juice PRIVATE USE_NETTLE=1)
    target_link_libraries(juice PRIVATE Nettle::Nettle)
    target_compile_definitions(juice-static PRIVATE USE_NETTLE=1)
    target_link_libraries(juice-static PRIVATE Nettle::Nettle)
else()
    target_compile_definitions(juice PRIVATE USE_NETTLE=0)
    target_compile_definitions(juice-static PRIVATE USE_NETTLE=0)
endif()

if (NO_SERVER)
	target_compile_definitions(juice PRIVATE NO_SERVER)
	target_compile_definitions(juice-static PRIVATE NO_SERVER)
endif()

if (NO_ATOMICS)
	target_compile_definitions(juice PRIVATE NO_ATOMICS)
	target_compile_definitions(juice-static PRIVATE NO_ATOMICS)
endif()

if(APPLE)
	# This seems to be necessary on MacOS
	target_include_directories(juice PRIVATE /usr/local/include)
	target_include_directories(juice-static PRIVATE /usr/local/include)
endif()

add_library(LibJuice::LibJuice ALIAS juice)
add_library(LibJuice::LibJuiceStatic ALIAS juice-static)

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.12")
	include(GenerateExportHeader)
	generate_export_header(juice)
	target_include_directories(juice PUBLIC ${CMAKE_BINARY_DIR})
	target_compile_definitions(juice PUBLIC -DJUICE_HAS_EXPORT_HEADER)
	set_target_properties(juice PROPERTIES C_VISIBILITY_PRESET hidden)
	install(FILES ${PROJECT_BINARY_DIR}/juice_export.h DESTINATION include/juice)
endif()

install(TARGETS juice LIBRARY DESTINATION lib)
install(FILES ${LIBJUICE_HEADERS} DESTINATION include/juice)

if(NOT MSVC)
	target_compile_options(juice PRIVATE -Wall -Wextra)
	target_compile_options(juice-static PRIVATE -Wall -Wextra)
endif()

if(WARNINGS_AS_ERRORS)
	if(MSVC)
		target_compile_options(juice PRIVATE /WX)
		target_compile_options(juice-static PRIVATE /WX)
	else()
		target_compile_options(juice PRIVATE -Werror)
		target_compile_options(juice-static PRIVATE -Werror)
	endif()
endif()

if(ENABLE_LOCALHOST_ADDRESS)
	target_compile_definitions(juice PRIVATE JUICE_ENABLE_LOCALHOST_ADDRESS=1)
endif()

if(ENABLE_LOCAL_ADDRESS_TRANSLATION)
	target_compile_definitions(juice PRIVATE JUICE_ENABLE_LOCAL_ADDRESS_TRANSLATION=1)
endif()

# Tests
if(NOT NO_TESTS)
	add_executable(juice-tests ${TESTS_SOURCES})
	target_include_directories(juice-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
	target_include_directories(juice-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)
	set_target_properties(juice-tests PROPERTIES VERSION ${PROJECT_VERSION})
	set_target_properties(juice-tests PROPERTIES OUTPUT_NAME tests)
	set_target_properties(juice-tests PROPERTIES
		XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER com.github.paullouisageneau.libjuice.tests)
	target_link_libraries(juice-tests juice)
endif()

