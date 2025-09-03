cmake_minimum_required(VERSION 3.18)
project(MonteCarloCUDA LANGUAGES CXX CUDA)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
execute_process(
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
)

include_directories(${PROJECT_NAME} PRIVATE include)
file(GLOB SOURCES src/*.cpp src/*.cu)

find_package(CUDAToolkit REQUIRED)
if(CUDAToolkit_FOUND)
  MESSAGE(STATUS "Include DIRS: ${CUDAToolkit_INCLUDE_DIRS}")
  MESSAGE(STATUS "Link libraries: ${CUDAToolkit_LIBS}")
else()
  MESSAGE(FATAL_ERROR "CUDAToolkit not found.")
endif()

# set(CMAKE_CUDA_ARCHITECTURES "61")
add_executable(${PROJECT_NAME} ${SOURCES})
# target_link_libraries(${PROJECT_NAME} PRIVATE CUDA::cudart)
