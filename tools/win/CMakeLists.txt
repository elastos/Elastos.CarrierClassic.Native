cmake_minimum_required(VERSION 3.5)
cmake_policy(VERSION 3.5)
project(vstool VERSION 1.0.1)

message("================================")
message("CMake command line for Windows:")
message("cmake -G \"NMake Makefiles\" -DCMAKE_VS_PLATFORM_TOOLSET=${CMAKE_VS_PLATFORM_TOOLSET} -DCMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION=${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION} ...")
message("================================")
