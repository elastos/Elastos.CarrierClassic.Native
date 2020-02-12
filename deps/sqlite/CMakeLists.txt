project(sqlite)

include(CarrierDefaults)
include(ExternalProject)

set(PATCH_EXE "echo")
set(PATCH_ARGS "Done")

set(CONFIGURE_CMD "./configure")
set(CONFIGURE_ARGS
    "--prefix=${CARRIER_INT_DIST_DIR}"
    "--enable-shared=no"
    "--disable-shared"
    "--enable-static=yes")

set(BUILD_CMD "make")

set(INSTALL_CMD "make")
set(INSTALL_ARGS "install")

ExternalProject_Add(
    sqlite

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    URL "https://www.sqlite.org/2019/sqlite-autoconf-3300100.tar.gz"
    URL_HASH SHA256=8c5a50db089bd2a1b08dbc5b00d2027602ca7ff238ba7658fabca454d4298e60
    DOWNLOAD_NAME "sqlite-autoconf-3300100.tar.gz"
    DOWNLOAD_DIR ${CARRIER_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    EXCLUDE_FROM_ALL TRUE

    BUILD_IN_SOURCE 1

    PATCH_COMMAND ${PATCH_EXE} ${PATCH_ARGS}
    CONFIGURE_COMMAND ${CONFIGURE_CMD} ${CONFIGURE_ARGS}
    BUILD_COMMAND ${BUILD_CMD} ${BUILD_ARGS}
    INSTALL_COMMAND ${INSTALL_CMD} ${INSTALL_ARGS}
)
