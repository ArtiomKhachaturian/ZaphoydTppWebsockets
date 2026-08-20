add_executable(${PROJECT_NAME}Tests
    FactoryTests.cpp
    support/LocalEchoServer.h
    support/LocalEchoServer.cpp
    support/RecordingListener.h
    support/TestBlob.h
)

target_include_directories(${PROJECT_NAME}Tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/websockets_api/include
    ${CMAKE_SOURCE_DIR}/bricks/include
    ${CMAKE_SOURCE_DIR}/bricks/include/listeners
    ${CMAKE_SOURCE_DIR}/bricks/include/logger
    ${CMAKE_SOURCE_DIR}/bricks/include/threadsafety
    ${TPP_HDRS_DIR}
    ${ASIO_HDRS_DIR}
)

if (WIN32)
    target_compile_definitions(${PROJECT_NAME}Tests PRIVATE
        -D_WEBSOCKETPP_CPP11_STL_
        -DUNICODE
        -DNOMINMAX
        -DWIN32_LEAN_AND_MEAN
        -D_ENABLE_EXTENDED_ALIGNED_STORAGE
    )
endif()
target_compile_definitions(${PROJECT_NAME}Tests PRIVATE
    -DASIO_STANDALONE
    -DASIO_DISABLE_VISIBILITY
)

target_link_libraries(${PROJECT_NAME}Tests PRIVATE
    ${PROJECT_NAME}
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME}Tests)
