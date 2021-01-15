project(elastos-carrier C)
cmake_policy(SET CMP0054 NEW)

include(CarrierDefaults)
include(CheckIncludeFile)

check_include_file(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
    add_definitions(-DHAVE_UNISTD_H=1)
endif()

check_include_file(alloca.h HAVE_ALLOCA_H)
if(HAVE_ALLOCA_H)
    add_definitions(-DHAVE_ALLOCA_H=1)
endif()

check_include_file(malloc.h HAVE_MALLOC_H)
if(HAVE_MALLOC_H)
    add_definitions(-DHAVE_MALLOC_H=1)
endif()

check_include_file(io.h HAVE_IO_H)
if(HAVE_IO_H)
    add_definitions(-DHAVE_IO_H=1)
endif()

check_include_file(direct.h HAVE_DIRECT_H)
if(HAVE_DIRECT_H)
    add_definitions(-DHAVE_DIRECT_H=1)
endif()

check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
if(HAVE_ARPA_INET_H)
    add_definitions(-DHAVE_ARPA_INET_H=1)
endif()

check_include_file(winsock2.h HAVE_WINSOCK2_H)
if(HAVE_WINSOCK2_H)
    add_definitions(-DHAVE_WINSOCK2_H=1)
endif()

check_include_file(ws2tcpip.h HAVE_WS2TCPIP_H)
if(HAVE_WS2TCPIP_H)
    add_definitions(-DHAVE_WS2TCPIP_H=1)
endif()

check_include_file(sys/time.h HAVE_SYS_TIME_H)
if(HAVE_SYS_TIME_H)
    add_definitions(-DHAVE_SYS_TIME_H=1)
endif()

check_include_file(sys/param.h HAVE_SYS_PARAM_H)
if(HAVE_SYS_PARAM_H)
    add_definitions(-DHAVE_SYS_PARAM_H=1)
endif()

configure_file(
    version.h.in
    version.h
    "@ONLY")

set(SRC
    dht/dht.c
    packet.c
    carrier.c
    carrier_error.c
    carrier_extension.c
    carrier_turnserver.c
    http_client.c
    express.c
    managed_group_client.c
    managed_group_server.c)

set(HEADERS
    carrier.h
    carrier_deprecated.h)

add_custom_command(
    OUTPUT packet_generated.h
    COMMAND ${CARRIER_HOST_TOOLS_DIR}/bin/flatcc${CMAKE_EXECUTABLE_SUFFIX}
        --outfile packet_generated.h
        -a "${CMAKE_CURRENT_LIST_DIR}/packet.fbs"
    DEPENDS "${CMAKE_CURRENT_LIST_DIR}/packet.fbs" flatcc-parser)

add_custom_target(packet_generated_h
    DEPENDS packet_generated.h)

if(WIN32)
    set(SYSTEM_LIBS Ws2_32 Iphlpapi)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(SYSTEM_LIBS pthread m)
endif()

include_directories(
    .
    dht
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CARRIER_INT_DIST_DIR}/include)

link_directories(
    ${CARRIER_INT_DIST_DIR}/lib)

if(WIN32)
    add_definitions(
        -DWIN32_LEAN_AND_MEAN
        -D_CRT_SECURE_NO_WARNINGS
        -D_CRT_NONSTDC_NO_WARNINGS)

    # Force source code encoding to utf-8
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /utf-8")
endif()

set(LIBS
    cjson
    libcurl
    crystal
    toxcore
    flatccrt
    sqlite3)

if(WIN32)
    set(LIBS
        ${LIBS}
        pthread
        libsodium.lib)
else()
    set(LIBS
        ${LIBS}
        sodium
        dl)
endif()

add_definitions(-DCARRIER_BUILD)

add_custom_target(carrier0)

if(ENABLE_STATIC)
    add_library(carrier-static STATIC ${SRC})

    target_compile_definitions(carrier-static PRIVATE CARRIER_STATIC CRYSTAL_STATIC)
    set_target_properties(carrier-static PROPERTIES OUTPUT_NAME carrier)
    if(WIN32)
        set_target_properties(carrier-static PROPERTIES LINK_FLAGS /FORCE:MULTIPLE)
    endif()
    add_dependencies(carrier-static packet_generated_h)

    add_dependencies(carrier0 carrier-static)

    install(TARGETS carrier-static
        RUNTIME DESTINATION "bin"
        ARCHIVE DESTINATION "lib"
        LIBRARY DESTINATION "lib")
endif()

if(ENABLE_SHARED)
    add_library(carrier-shared SHARED ${SRC})

    target_compile_definitions(carrier-shared PRIVATE CARRIER_DYNAMIC CRYSTAL_DYNAMIC)
    set_target_properties(carrier-shared PROPERTIES OUTPUT_NAME carrier)
    if(WIN32)
        set_target_properties(carrier-shared PROPERTIES LINK_FLAGS /FORCE:MULTIPLE)
    endif()
    target_link_libraries(carrier-shared ${LIBS} ${SYSTEM_LIBS})
    add_dependencies(carrier-shared packet_generated_h)

    add_dependencies(carrier0 carrier-shared)

    install(TARGETS carrier-shared
        RUNTIME DESTINATION "bin"
        ARCHIVE DESTINATION "lib"
        LIBRARY DESTINATION "lib")
endif()

install(FILES ${HEADERS} DESTINATION "include")
