project(libcrystal)

include(CarrierDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
    libcrystal

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    URL "https://github.com/iwhisperio/libcrystal/archive/release-v1.0.6.tar.gz"
    URL_HASH SHA256=24513b4f8971a35a4fd29f85f21dba2ae55e06fe5fe34a533a3013da98a2c98b
    DOWNLOAD_NAME "libcrystal-v1.0.6.tar.gz"
    DOWNLOAD_DIR ${CARRIER_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1

    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CARRIER_INT_DIST_DIR}
        -DENABLE_STATIC=${ENABLE_STATIC}
        -DENABLE_SHARED=${ENABLE_SHARED}
        -DLIBSODIUM_STATIC=TRUE
        -DENABLE_CRYPTO=TRUE
        -DENABLE_TESTS=FALSE
        ${CMAKE_ARGS_INIT}
)

if(ENABLE_STATIC)
    export_static_library(crystal)
endif()

if(ENABLE_SHARED)
    export_shared_library(crystal)
endif()
