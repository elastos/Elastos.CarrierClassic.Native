project(toxcore)

include(CarrierDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
    toxcore0

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    URL "https://github.com/elastos/c-toxcore/archive/v0.2.12.carrier.tar.gz"
    URL_HASH SHA256=318c69bd27c0af6fa9cf277caba1e610df5af5f13acc5304024a50d9e4231da7
    DOWNLOAD_NAME "c-toxcore-0.2.12.carrier.tar.gz"
    DOWNLOAD_DIR ${CARRIER_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CARRIER_INT_DIST_DIR}
        -DCMAKE_USE_SLIM_PTHREAD_INIT=TRUE
        -DENABLE_SHARED=OFF
        -DENABLE_STATIC=ON
        -DBUILD_TOXAV=OFF
        -DDHT_BOOTSTRAP=OFF
        -DBUILD_CARRIER=ON
        ${CMAKE_ARGS_INIT}
)

if(ENABLE_STATIC)
    export_static_library(toxcore)
endif()
