cmake_minimum_required (VERSION 3.10)
project (libjuice
	VERSION 1.6.1
	LANGUAGES C)
set(PROJECT_DESCRIPTION "UDP Interactive Connectivity Establishment (ICE) library")

option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(USE_NETTLE "Use Nettle for hash functions" OFF)
option(NO_SERVER "Disable server support" OFF)
option(NO_TESTS "Disable tests build" OFF)
option(WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(FUZZER "Enable oss-fuzz fuzzing" OFF)
option(CLANG_TIDY "Enable clang-tidy" OFF)

# Mitigations
option(DISABLE_CONSENT_FRESHNESS "Disable RFC 7675 Consent Freshness" OFF)
option(ENABLE_LOCALHOST_ADDRESS "List localhost addresses in candidates" OFF)
option(ENABLE_LOCAL_ADDRESS_TRANSLATION "Translate local addresses to localhost" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/Modules)

include(GNUInstallDirs)

if(WIN32)
	add_definitions(-DWIN32_LEAN_AND_MEAN)
	if (MSVC)
		add_definitions(-DNOMINMAX)
		add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	endif()
endif()

if(CLANG_TIDY)
	set(CMAKE_C_CLANG_TIDY clang-tidy)
endif()

set(LIBJUICE_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/src/addr.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/agent.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/crc32.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/const_time.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/conn.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/conn_poll.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/conn_thread.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/conn_mux.c
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
source_group("Source Files" FILES "${LIBJUICE_SOURCES}")

set(LIBJUICE_HEADERS
	${CMAKE_CURRENT_SOURCE_DIR}/include/juice/juice.h
)
source_group("Header Files" FILES "${LIBJUICE_HEADERS}")

set(TESTS_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/test/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/crc32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/stun-unhandled.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/stun-unhandled-multiple.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/stun-unhandled-no-host.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/stun-unhandled-unhandle.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/stun.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/gathering.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/connectivity.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/turn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/thread.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/mux.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/notrickle.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/server.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/conflict.c
    ${CMAKE_CURRENT_SOURCE_DIR}/test/bind.c
	${CMAKE_CURRENT_SOURCE_DIR}/test/ufrag.c
)
source_group("Test Files" FILES "${TESTS_SOURCES}")

set(FUZZER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzer/fuzzer.c
)
source_group("Fuzzer Files" FILES "${FUZZER_SOURCES}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_library(juice ${LIBJUICE_SOURCES})
set_target_properties(juice PROPERTIES VERSION ${PROJECT_VERSION})
target_include_directories(juice PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_include_directories(juice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)
target_include_directories(juice PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(juice PRIVATE $<$<CONFIG:Release>:RELEASE=1>)
target_link_libraries(juice PRIVATE Threads::Threads)

add_library(juice-static STATIC EXCLUDE_FROM_ALL ${LIBJUICE_SOURCES})
set_target_properties(juice-static PROPERTIES VERSION ${PROJECT_VERSION})
target_include_directories(juice-static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_include_directories(juice-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)
target_include_directories(juice-static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(juice-static PRIVATE $<$<CONFIG:Release>:RELEASE=1>)
target_link_libraries(juice-static PRIVATE Threads::Threads)

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

if(APPLE)
	# This seems to be necessary on MacOS
	target_include_directories(juice PRIVATE /usr/local/include)
	target_include_directories(juice-static PRIVATE /usr/local/include)
endif()

set_target_properties(juice PROPERTIES EXPORT_NAME LibJuice)
add_library(LibJuice::LibJuice ALIAS juice)

set_target_properties(juice-static PROPERTIES EXPORT_NAME LibJuiceStatic)
add_library(LibJuice::LibJuiceStatic ALIAS juice-static)

install(TARGETS juice EXPORT LibJuiceTargets
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES ${LIBJUICE_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/juice)

# Export targets
install(
	EXPORT LibJuiceTargets
	FILE LibJuiceTargets.cmake
	NAMESPACE LibJuice::
	DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibJuice
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/LibJuiceConfig.cmake.in
    ${CMAKE_BINARY_DIR}/LibJuiceConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibJuice
    NO_SET_AND_CHECK_MACRO
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
)
write_basic_package_version_file(
    ${CMAKE_BINARY_DIR}/LibJuiceConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
# Export config and version files
install(FILES
	${CMAKE_BINARY_DIR}/LibJuiceConfig.cmake
	${CMAKE_BINARY_DIR}/LibJuiceConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibJuice)

set_target_properties(juice PROPERTIES C_VISIBILITY_PRESET hidden)
target_compile_definitions(juice PRIVATE JUICE_EXPORTS)
if (NOT BUILD_SHARED_LIBS)
	target_compile_definitions(juice PUBLIC JUICE_STATIC)
endif()
target_compile_definitions(juice-static PRIVATE JUICE_EXPORTS)
target_compile_definitions(juice-static PUBLIC JUICE_STATIC)

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

if(DISABLE_CONSENT_FRESHNESS)
	target_compile_definitions(juice PRIVATE JUICE_DISABLE_CONSENT_FRESHNESS=1)
	target_compile_definitions(juice-static PRIVATE JUICE_DISABLE_CONSENT_FRESHNESS=1)
endif()

if(ENABLE_LOCALHOST_ADDRESS)
	target_compile_definitions(juice PRIVATE JUICE_ENABLE_LOCALHOST_ADDRESS=1)
	target_compile_definitions(juice-static PRIVATE JUICE_ENABLE_LOCALHOST_ADDRESS=1)
endif()

if(ENABLE_LOCAL_ADDRESS_TRANSLATION)
	target_compile_definitions(juice PRIVATE JUICE_ENABLE_LOCAL_ADDRESS_TRANSLATION=1)
	target_compile_definitions(juice-static PRIVATE JUICE_ENABLE_LOCAL_ADDRESS_TRANSLATION=1)
endif()

# Tests
if(NOT NO_TESTS)
	add_executable(juice-tests ${TESTS_SOURCES})
	target_include_directories(juice-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
	target_include_directories(juice-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)

	set_target_properties(juice-tests PROPERTIES
		VERSION ${PROJECT_VERSION}
		OUTPUT_NAME tests)

	set_target_properties(juice-tests PROPERTIES
		XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER com.github.paullouisageneau.libjuice.tests)

	target_link_libraries(juice-tests juice Threads::Threads)
endif()

# Fuzzer
if(FUZZER)
	add_executable(stun-fuzzer ${FUZZER_SOURCES})
	target_include_directories(stun-fuzzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
	target_include_directories(stun-fuzzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/juice)

	set_target_properties(stun-fuzzer PROPERTIES OUTPUT_NAME fuzzer)
	target_link_libraries(stun-fuzzer juice-static ${LIB_FUZZING_ENGINE})
endif()
