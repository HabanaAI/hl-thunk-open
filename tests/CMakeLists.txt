# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

project(libhl-thunk-tests C)

include_directories(
  ${CMOCKA_INCLUDE_DIR}
  ${CMAKE_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}
)
   
set(TEST_TARGET_LIBRARIES
    ${HLTHUNK_TARGET}
    ${CMOCKA_LIBRARY}
)

add_subdirectory(goya)
