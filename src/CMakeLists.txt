set(ELACARRIER_DEPENDS
    libcrystal
    toxcore0
    libsodium
    flatcc
    cJSON
    curl)

set(ELASESSION_DEPENDS
    libcrystal
    pjsip)

set(ELAFILE_DEPENDS
    libcrystal)

add_subdirectory(carrier)
add_subdirectory(session)
add_subdirectory(filetransfer)

if(ENABLE_STATIC)
    add_dependencies(carrier-static ${ELACARRIER_DEPENDS})
    add_dependencies(carriersession-static ${ELASESSION_DEPENDS} carrier-static)
    add_dependencies(carrierfiletrans-static ${elafile_DEPENDS} carrier-static)
    add_dependencies(carrierfiletrans-static ${elafile_DEPENDS} carriersession-static)
endif()

if(ENABLE_SHARED)
    add_dependencies(carrier-shared ${ELACARRIER_DEPENDS})
    add_dependencies(carriersession-shared ${ELASESSION_DEPENDS} carrier-shared)
    add_dependencies(carrierfiletrans-shared ${ELAFILE_DEPENDS} carrier-shared)
    add_dependencies(carrierfiletrans-shared ${ELAFILE_DEPENDS} carriersession-shared)
endif()
