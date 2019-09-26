message("\n src ...")

macro(install_symlink filepath sympath)
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${filepath} ${sympath})")
    install(CODE "LIST(APPEND CMAKE_INSTALL_MANIFEST_FILES ${sympath})")
    install(CODE "message(\"-- Created symlink: ${sympath} -> ${filepath}\")")
endmacro(install_symlink)

set(KS_INCLUDS_DESTINATION "${_INSTALL_PREFIX}/include/${KS_APP_NAME}")

message(STATUS "libkshark")
add_library(kshark SHARED libkshark.c
                          libkshark-tepdata.c
                          libkshark-hash.c
                          libkshark-model.c
                          libkshark-plugin.c
                          libkshark-configio.c
                          libkshark-collection.c)

target_link_libraries(kshark ${TRACEEVENT_LIBRARY}
                             ${TRACECMD_LIBRARY}
                             ${JSONC_LIBRARY}
                             ${CMAKE_DL_LIBS})

set_target_properties(kshark  PROPERTIES SUFFIX	".so.${KS_VERSION_STRING}")

install(TARGETS kshark LIBRARY DESTINATION ${_INSTALL_PREFIX}/lib/${KS_APP_NAME})

if (_DEVEL)

    install_symlink("libkshark.so.${KS_VERSION_STRING}"
                    "${_INSTALL_PREFIX}/lib/${KS_APP_NAME}/libkshark.so")

    install(FILES "${KS_DIR}/src/libkshark.h"
            DESTINATION ${KS_INCLUDS_DESTINATION})

endif (_DEVEL)

if (OPENGL_FOUND AND GLUT_FOUND)

    message(STATUS "libkshark-plot")
    add_library(kshark-plot  SHARED  libkshark-plot.c
                                     KsPlotTools.cpp)

    target_link_libraries(kshark-plot  kshark
                                       ${GLUT_LIBRARY}
                                       ${OPENGL_LIBRARIES})

    set_target_properties(kshark-plot PROPERTIES  SUFFIX ".so.${KS_VERSION_STRING}")

    install(TARGETS kshark-plot LIBRARY DESTINATION ${_INSTALL_PREFIX}/lib/${KS_APP_NAME}
                                COMPONENT core)

    if (_DEVEL)

        install_symlink("libkshark-plot.so.${KS_VERSION_STRING}"
                        "${_INSTALL_PREFIX}/lib/${KS_APP_NAME}/libkshark-plot.so")

        install(FILES "${KS_DIR}/src/KsPlotTools.hpp"
                      "${KS_DIR}/src/libkshark-plot.h"
                DESTINATION ${KS_INCLUDS_DESTINATION}
                COMPONENT devel)

    endif (_DEVEL)

endif (OPENGL_FOUND AND GLUT_FOUND)

add_subdirectory(plugins)

find_program(DO_AS_ROOT pkexec)

configure_file( ${KS_DIR}/build/deff.h.cmake
                ${KS_DIR}/src/KsCmakeDef.hpp)
