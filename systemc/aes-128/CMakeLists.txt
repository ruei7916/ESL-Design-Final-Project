cmake_minimum_required(VERSION 3.0)

# Define the project name of these source code
project (aes)

# We use a CMake module to fine the SystemC library. Define the module path
set (CMAKE_PREFIX_PATH $ENV{SYSTEMC_HOME})

# Find the package, which defines variable SYSTEMC_INCLUDE_DIRS
# and SYSTEMC_LIBRARIES.
find_package(SystemCLanguage CONFIG REQUIRED)

# Make Compiler option aligned to SystemC
set (CMAKE_CXX_STANDARD ${SystemC_CXX_STANDARD} CACHE STRING
     "C++ standard to build all targets. Supported values are 98, 11, and 14.")
set (CMAKE_CXX_STANDARD_REQUIRED ${SystemC_CXX_STANDARD_REQUIRED} CACHE BOOL
     "The with CMAKE_CXX_STANDARD selected C++ standard is a requirement.")

# Add optimization & warning flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall")

# Set clock period = 1 ns
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D CLOCK_PERIOD=1.0 -D NATIVE_SYSTEMC")

# Define the executable name and its source code
file(GLOB SRC "*.cpp")
add_executable(aes ${SRC})

# Define the used libraries of the executable, Equal to -l flags of g++
# In here, the libraries are given in apsolute path. hence no needs for -L
# flag
target_link_libraries(aes SystemC::systemc)

# Add test sobel filter command
set(OUT_FILE "out")
add_custom_command(OUTPUT ${OUT_FILE}
	COMMAND ./aes ../key ../plaintext ./${OUT_FILE}
	DEPENDS aes
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}	
)
add_custom_target(run 
	DEPENDS ${OUT_FILE}
)


