CMAKE_MINIMUM_REQUIRED(VERSION 3.29)
PROJECT(pcap2json)
SET(TARGET_NAME pcap2json)

SET(CMAKE_CXX_STANDARD 20)
SET(TARGET_DIR ${PROJECT_SOURCE_DIR}/target)

INCLUDE(${PROJECT_SOURCE_DIR}/cmake/ansi.cmake)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include)

AUX_SOURCE_DIRECTORY(source SOURCE_FILE)
ADD_EXECUTABLE(${TARGET_NAME} main.cpp ${SOURCE_FILE})

TARGET_LINK_LIBRARIES(${TARGET_NAME} PUBLIC pcap)

ADD_CUSTOM_COMMAND(
    TARGET ${TARGET_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "$<TARGET_FILE:${TARGET_NAME}>"
    "${TARGET_DIR}"
    COMMENT "复制成果物 ${TARGET_NAME} 到 ${TARGET_DIR}"
)

SET(_packaging_dir ${PROJECT_BINARY_DIR}/target)
SET(_packaging_filename ${PROJECT_SOURCE_DIR}/${CMAKE_BUILD_TYPE}.zip)
ADD_CUSTOM_TARGET(
    PackageAndOpen
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_packaging_dir}"
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${TARGET_DIR}" "${_packaging_dir}"
    COMMAND ${CMAKE_COMMAND} -E tar cf ${_packaging_filename} --format=zip -- "${_packaging_dir}"
    COMMAND ${CMAKE_COMMAND} -E echo "\t- create archive: ${_packaging_filename}"
    COMMAND ${CMAKE_COMMAND} -E remove_directory "${_packaging_dir}"
    COMMAND ${CMAKE_COMMAND} -E chdir ${PROJECT_SOURCE_DIR} ${CMAKE_COMMAND} -E echo "\t- opening location..."
    COMMAND open "${PROJECT_SOURCE_DIR}/"
    COMMENT "打包成果物并打开所在路径"
)