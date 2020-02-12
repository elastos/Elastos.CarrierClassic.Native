include(AddSubModule)

set(DEPEND_MODULES
    libcrystal
    libconfig
    ela-carrier
    ela-session)

add_submodule(elashell
    DIRECTORY shell
    DEPENDS ${DEPEND_MODULES})

add_submodule(elapfd
    DIRECTORY pfd
    DEPENDS ${DEPEND_MODULES})

add_submodule(elafile
    DIRECTORY file
    DEPENDS ${DEPEND_MODULES} ela-filetransfer)

# add_submodule(fileonce
#     DIRECTORY fileonce
#     DEPENDS ${DEPEND_MODULES} ela-filetransfer)

add_submodule(elaerr
    DIRECTORY errstr
    DEPENDS ${DEPEND_MODULES})

if (NOT WIN32)
    add_submodule(elaspeedtest
        DIRECTORY speedtest
        DEPENDS ${DEPEND_MODULES})
endif()

if((${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux" OR
    ${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Darwin") AND
    NOT CMAKE_CROSSCOMPILING)
    add_subdirectory(feeds)
    add_dependencies(service_feeds
        cJSON libconfig libcrystal ela-carrier sqlite)
    add_dependencies(feeds_cli
        cJSON libconfig libcrystal ela-carrier)
endif()
