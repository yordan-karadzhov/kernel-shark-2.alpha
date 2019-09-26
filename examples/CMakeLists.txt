message("\n examples ...")

message(STATUS "dataload")
add_executable(dload          dataload.c)
target_link_libraries(dload   kshark)

message(STATUS "datafilter")
add_executable(dfilter          datafilter.c)
target_link_libraries(dfilter   kshark)

message(STATUS "dataplot")
add_executable(dplot          dataplot.cpp)
target_link_libraries(dplot   kshark-plot)

add_library(hello             SHARED  hello_kernel.c)
set_target_properties(hello   PROPERTIES PREFIX "plugin-")
target_link_libraries(hello   kshark-plot)
