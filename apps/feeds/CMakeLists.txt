include(CarrierDefaults)
include(CheckIncludeFile)
include(CheckFunctionExists)

check_include_file(alloca.h HAVE_ALLOCA_H)
if(HAVE_ALLOCA_H)
    add_definitions(-DHAVE_ALLOCA_H=1)
endif()

check_include_file(malloc.h HAVE_MALLOC_H)
if(HAVE_MALLOC_H)
    add_definitions(-DHAVE_MALLOC_H=1)
endif()

check_include_file(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
    add_definitions(-DHAVE_UNISTD_H=1)
endif()

check_include_file(getopt.h HAVE_GETOPT_H)
if(HAVE_GETOPT_H)
    add_definitions(-DHAVE_GETOPT_H=1)
endif()

check_include_file(process.h HAVE_PROCESS_H)
if(HAVE_PROCESS_H)
    add_definitions(-DHAVE_PROCESS_H=1)
endif()

check_include_file(sys/time.h HAVE_SYS_TIME_H)
if(HAVE_SYS_TIME_H)
    add_definitions(-DHAVE_SYS_TIME_H=1)
endif()

check_include_file(sys/resource.h HAVE_SYS_RESOURCE_H)
if(HAVE_SYS_RESOURCE_H)
    add_definitions(-DHAVE_SYS_RESOURCE_H=1)
endif()

check_include_file(sys/select.h HAVE_SYS_SELECT_H)
if(HAVE_SYS_SELECT_H)
    add_definitions(-DHAVE_SYS_SELECT_H=1)
endif()

check_include_file(direct.h HAVE_DIRECT_H)
if(HAVE_DIRECT_H)
    add_definitions(-DHAVE_DIRECT_H=1)
endif()

check_function_exists(sigaction HAVE_SIGACTION)
if(HAVE_SIGACTION)
    add_definitions(-DHAVE_SIGACTION=1)
endif()

set(SRC
    db.c
    jsonrpc.c
    carrier_transport.c
    carrier_config.c
    config.c
    error_code.c
    service_feeds.c
    mkdirs.c)

include_directories(
    .
    ../../src/carrier
    ${CARRIER_INT_DIST_DIR}/include)

link_directories(
    ${CARRIER_INT_DIST_DIR}/lib
    ${CMAKE_CURRENT_BINARY_DIR}/../../src/carrier)

set(LIBS
    cjson
    sqlite3
    config
    crystal
    elacarrier
    pthread
    dl
    m)

add_executable(service_feeds ${SRC})
set_target_properties(service_feeds PROPERTIES OUTPUT_NAME svc_feeds)
target_link_libraries(service_feeds ${LIBS})
install(TARGETS service_feeds
    RUNTIME DESTINATION "bin"
    ARCHIVE DESTINATION "lib"
    LIBRARY DESTINATION "lib")

set(SRC
    jsonrpc.c
    carrier_transport.c
    carrier_config.c
    error_code.c
    feeds_client/feeds_cli.c
    feeds_client/feeds_client.c)

set(LIBS
    cjson
    config
    crystal
    elacarrier
    pthread)

add_executable(feeds_cli ${SRC})
set_target_properties(feeds_cli PROPERTIES OUTPUT_NAME feeds_cli)
target_link_libraries(feeds_cli ${LIBS})
install(TARGETS feeds_cli
    RUNTIME DESTINATION "bin"
    ARCHIVE DESTINATION "lib"
    LIBRARY DESTINATION "lib")

install(FILES feeds.conf
    DESTINATION "etc/carrier")
