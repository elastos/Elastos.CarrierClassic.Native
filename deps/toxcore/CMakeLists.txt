project(toxcore)

include(CarrierDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
    toxcore0

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    URL "https://github.com/elastos/c-toxcore/archive/carrier.zip"
    URL_HASH SHA256=280f7cbdf0f4e0766de0867c61e2f0ea9a5ef9b42be86d4696a4052c6b19fcc1
    DOWNLOAD_NAME "c-toxcore-carrier.zip"
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
