project(libcrystal)

include(CarrierDefaults)
include(ExternalProject)
include(ExternalCMakeArgs)

ExternalProject_Add(
    libcrystal

    PREFIX ${CARRIER_DEPS_BUILD_PREFIX}
    URL "https://github.com/iwhisperio/libcrystal/archive/v1.0.3.tar.gz"
    URL_HASH SHA256=867200b6e0314a69b7dc9792bc05f18a75f375ce4332127caa4a73630814af06
    DOWNLOAD_NAME "libcrystal-v1.0.3.tar.gz"
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

if(ENABLE_SHARED)
    if(WIN32)
        set(INSTALL_DESTINATION bin)
    else()
        set(INSTALL_DESTINATION lib)
    endif()

    string(CONCAT SHARED_LIBRARY_NAME
        "${CARRIER_INT_DIST_DIR}/${INSTALL_DESTINATION}/"
        "${CMAKE_SHARED_LIBRARY_PREFIX}"
        "crystal"
        "${CMAKE_SHARED_LIBRARY_SUFFIX}")

    file(RELATIVE_PATH SHARED_LIBRARY_NAME ${CMAKE_CURRENT_LIST_DIR}
        ${SHARED_LIBRARY_NAME})

    install(PROGRAMS "${SHARED_LIBRARY_NAME}"
        DESTINATION ${INSTALL_DESTINATION})
endif()
