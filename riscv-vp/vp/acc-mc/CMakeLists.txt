file(GLOB_RECURSE HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.h)

add_library(platform-acc-mc
ethernet.cpp
display.cpp
${HEADERS})

target_include_directories(platform-acc-mc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(platform-acc-mc systemc)

add_executable(riscv-vp-acc-mc
        main.cpp)

target_link_libraries(riscv-vp-acc-mc rv32 platform-acc-mc platform-common gdb-mc ${Boost_LIBRARIES} systemc pthread)

INSTALL(TARGETS riscv-vp-acc-mc RUNTIME DESTINATION bin)
