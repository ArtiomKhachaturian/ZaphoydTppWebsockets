cmake_minimum_required(VERSION 3.15)

# Project name
project("ZaphoydTppWebsockets" LANGUAGES CXX VERSION 0.0.1)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# -fvisibility=hidden
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH ON)
set(CMAKE_BUILD_RPATH_USE_ORIGIN ON)


set(HEADER_FILE_EXT h)
set(SOURCE_FILE_EXT cpp)

function(recreateDir DIR)
    if (EXISTS ${DIR})
        file(REMOVE_RECURSE ${DIR})
    endif()
    file(MAKE_DIRECTORY ${DIR})
endfunction(recreateDir)

function(downloadAndExtract ZIP_URL ZIP_FILE EXTRACT_DIR)
    if (NOT EXISTS ${ZIP_FILE})
        message(STATUS "Downloading of ${ZIP_URL}")
        file(DOWNLOAD ${ZIP_URL} ${ZIP_FILE} SHOW_PROGRESS)
        recreateDir(${EXTRACT_DIR})
        file(ARCHIVE_EXTRACT INPUT ${ZIP_FILE} DESTINATION ${EXTRACT_DIR})
    endif()
endfunction(downloadAndExtract)

function(findOpenSSL)
    # Specify search paths in CMAKE_PREFIX_PATH variable (if needed): "/path/to/module_a;/another/path/to/module_b"
    find_package(OpenSSL)
    if (${OpenSSL_FOUND})
        message(STATUS "Found OpenSSL")
    else()
        set(OPENSSL_INCLUDE_DIR $ENV{OPENSSL_INCLUDE_DIR} CACHE PATH "Path to folder with OpenSSL headers")
        set(OPENSSL_LIB_DIR $ENV{OPENSSL_LIB_DIR} CACHE PATH "Path to folder with OpenSSL libraries")
        if (EXISTS ${OPENSSL_LIB_DIR})
            set(OPENSSL_LIBS ssl crypto)
            set(OPENSSL_LIBRARIES "")
            foreach(OPENSSL_LIB ${OPENSSL_LIBS})
                if (WIN32)
                    set(OPENSSL_LIB "${OPENSSL_LIB_DIR}\\lib${OPENSSL_LIB}.lib")
                else()
                    set(OPENSSL_LIB "${OPENSSL_LIB_DIR}/lib${OPENSSL_LIB}.dylib")
                endif()
                if (EXISTS ${OPENSSL_LIB})
                    list(APPEND OPENSSL_LIBRARIES ${OPENSSL_LIB})
                else()
                    message(FATAL_ERROR "OpenSSL library ${OPENSSL_LIB} was not found")
                endif()
            endforeach()
        else()
            message(FATAL_ERROR "Not found OpenSSL, try to set the path to OpenSSL lib folder in the system variable OPENSSL_LIB_DIR")
        endif()
    endif()
    set(OPENSSL_LIBRARIES ${OPENSSL_LIBRARIES} PARENT_SCOPE)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR} PARENT_SCOPE)
    message(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OPENSSL_LIBRARIES = ${OPENSSL_LIBRARIES}")
endfunction(findOpenSSL)

findOpenSSL()
option(SHARED_IO_SERVICE "Common I/O worker thread for all websockets instances" ON)
set(TPP_ZIP_URL "https://github.com/zaphoyd/websocketpp/archive/refs/heads/master.zip")
set(TPP_SRC_DIR ${CMAKE_BINARY_DIR}/zaphoyd_tpp_src)
set(ASIO_ZIP_URL "https://sourceforge.net/projects/asio/files/asio/1.30.2%20%28Stable%29/asio-1.30.2.tar.gz/download")
set(ASIO_SRC_DIR ${CMAKE_BINARY_DIR}/asio_src)
downloadAndExtract(${TPP_ZIP_URL} ${CMAKE_BINARY_DIR}/zaphoyd_tpp.zip ${TPP_SRC_DIR})
downloadAndExtract(${ASIO_ZIP_URL} ${CMAKE_BINARY_DIR}/asio.zip ${ASIO_SRC_DIR})
set(TPP_HDRS_DIR ${TPP_SRC_DIR}/websocketpp-master)
set(ASIO_HDRS_DIR ${ASIO_SRC_DIR}/asio-1.30.2/include)
# Specify source files
file(GLOB_RECURSE PUBLIC_HEADERS ${CMAKE_SOURCE_DIR}/include/*.${HEADER_FILE_EXT})
file(GLOB_RECURSE COMMON_SOURCES ${CMAKE_SOURCE_DIR}/src/*.${SOURCE_FILE_EXT})
file(GLOB_RECURSE COMMON_HEADERS ${CMAKE_SOURCE_DIR}/src/*.${HEADER_FILE_EXT})
file(GLOB_RECURSE WEBSOCKETS_API_HEADERS ${CMAKE_SOURCE_DIR}/websockets_api/include/*.${HEADER_FILE_EXT})
file(GLOB_RECURSE BRICKS_API_HEADERS ${CMAKE_SOURCE_DIR}/bricks/include/*.${HEADER_FILE_EXT})

# Create a static library
add_library(${PROJECT_NAME} SHARED
    ${PUBLIC_HEADERS}
    ${COMMON_HEADERS}
    ${COMMON_SOURCES}
    ${WEBSOCKETS_API_HEADERS}
    ${BRICKS_API_HEADERS}
)

source_group(TREE ${CMAKE_SOURCE_DIR}/include PREFIX "PublicHeaders" FILES ${PUBLIC_HEADERS})
source_group(TREE ${CMAKE_SOURCE_DIR}/src PREFIX "Sources" FILES ${COMMON_HEADERS} ${COMMON_SOURCES})
source_group(TREE ${CMAKE_SOURCE_DIR}/websockets_api/include PREFIX "WebsocketsAPI" FILES ${WEBSOCKETS_API_HEADERS})
source_group(TREE ${CMAKE_SOURCE_DIR}/bricks/include PREFIX "Bricks" FILES ${BRICKS_API_HEADERS})

# Add include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/service
    ${CMAKE_SOURCE_DIR}/websockets_api/include
    ${CMAKE_SOURCE_DIR}/bricks/include
    ${CMAKE_SOURCE_DIR}/bricks/include/logger
    ${CMAKE_SOURCE_DIR}/bricks/include/threadsafety
    ${TPP_HDRS_DIR}
    ${ASIO_HDRS_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Generic attributes for the library
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE YES SOVERSION ${PROJECT_VERSION} VERSION ${PROJECT_VERSION})
if (WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE -D_WEBSOCKETPP_CPP11_STL_ -DUNICODE 
        -DNOMINMAX -DWIN32_LEAN_AND_MEAN -D_ENABLE_EXTENDED_ALIGNED_STORAGE)
    target_link_libraries(${PROJECT_NAME} PUBLIC "ws2_32.lib")
endif()
if (SHARED_IO_SERVICE)
    target_compile_definitions(${PROJECT_NAME} PRIVATE -DWEBSOCKETS_TPP_SHARED_IO_SERVICE)
endif(SHARED_IO_SERVICE)
target_compile_definitions(${PROJECT_NAME} PRIVATE -DASIO_STANDALONE -DZAPHOYD_TPP_EXPORTS -DPROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(${PROJECT_NAME} PUBLIC ${OPENSSL_LIBRARIES})

if (CMAKE_INSTALL_PREFIX)
    set(CMAKE_INSTALL_LIBDIR ${CMAKE_INSTALL_PREFIX}/lib)
    install(TARGETS ${PROJECT_NAME} 
            EXPORT ${PROJECT_NAME}Targets
            ARCHIVE DESTINATION lib 
            LIBRARY DESTINATION lib 
            RUNTIME DESTINATION bin)
    # public API installation
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/include DESTINATION .)
    install(FILES ${WEBSOCKETS_API_HEADERS} DESTINATION ./include)
    install(FILES ${CMAKE_SOURCE_DIR}/bricks/include/Blob.h DESTINATION ./include)

    # generate [config.cmake] and [config-version.cmake] files
    configure_package_config_file(./Config.cmake.in
        "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
      )
    install(FILES "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake" DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")

    write_basic_package_version_file(
        "${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
        COMPATIBILITY SameMajorVersion)

    install(FILES "${PROJECT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")

    # install targets file
    install(EXPORT "${PROJECT_NAME}Targets" DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
endif(CMAKE_INSTALL_PREFIX)