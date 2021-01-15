project(sqlite)

include(CarrierDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)
include(ExternalConfigureArgs)

if(WIN32)
    set(CONFIGURE_CMD ${CMAKE_COMMAND})
    set(CONFIGURE_ARGS
        -G "NMake Makefiles"
        -DCMAKE_INSTALL_PREFIX=${CARRIER_INT_DIST_DIR}
        ${CMAKE_ARGS_INIT})

else()
    set(CONFIGURE_CMD ./configure)
    set(CONFIGURE_ARGS
        --prefix=${CARRIER_INT_DIST_DIR}
        --enable-shared=no
        --disable-shared
        --enable-static=yes
        ${CONFIGURE_ARGS_INIT})
endif()

ExternalProject_Add(
    sqlite

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    URL https://www.sqlite.org/2019/sqlite-autoconf-3300100.tar.gz
    URL_HASH SHA256=8c5a50db089bd2a1b08dbc5b00d2027602ca7ff238ba7658fabca454d4298e60
    DOWNLOAD_NAME sqlite-autoconf-3300100.tar.gz
    DOWNLOAD_DIR ${CARRIER_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    BUILD_IN_SOURCE 1

    PATCH_COMMAND ${PATCH_EXE} -s -p1 < ${CMAKE_CURRENT_LIST_DIR}/sqlite.patch
    CONFIGURE_COMMAND ${CONFIGURE_CMD} ${CONFIGURE_ARGS}
)