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
                             ${TRACEFS_LIBRARY}
                             ${JSONC_LIBRARY}
                             ${CMAKE_DL_LIBS})

set_target_properties(kshark  PROPERTIES SUFFIX	".so.${KS_VERSION_STRING}")

install(TARGETS kshark LIBRARY DESTINATION ${_INSTALL_PREFIX}/lib/${KS_APP_NAME})

if (_DEVEL)

    install_symlink("libkshark.so.${KS_VERSION_STRING}"
                    "${_INSTALL_PREFIX}/lib/${KS_APP_NAME}/libkshark.so")

    install(FILES "${KS_DIR}/src/libkshark.h"
                  "${KS_DIR}/src/libkshark-plugin.h"
                  "${KS_DIR}/src/libkshark-tepdata.h"
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

if (Qt5Widgets_FOUND AND Qt5Network_FOUND AND NOT _LIBS)

    message(STATUS "libkshark-gui")
    set (ks-guiLib_hdr  KsUtils.hpp
                        KsModels.hpp
                        KsGLWidget.hpp
                        KsSearchFSM.hpp
                        KsDualMarker.hpp
                        KsWidgetsLib.hpp
                        KsTraceGraph.hpp
                        KsTraceViewer.hpp
                        KsMainWindow.hpp
                        KsCaptureDialog.hpp
                        KsQuickContextMenu.hpp
                        KsAdvFilteringDialog.hpp)

    QT5_WRAP_CPP(ks-guiLib_hdr_moc ${ks-guiLib_hdr})

    add_library(kshark-gui  SHARED  ${ks-guiLib_hdr_moc}    KsUtils.cpp
                                                            KsModels.cpp
                                                            KsPlugins.cpp
                                                            KsSession.cpp
                                                            KsGLWidget.cpp
                                                            KsSearchFSM.cpp
                                                            KsDualMarker.cpp
                                                            KsWidgetsLib.cpp
                                                            KsTraceGraph.cpp
                                                            KsTraceViewer.cpp
                                                            KsMainWindow.cpp
                                                            KsCaptureDialog.cpp
                                                            KsQuickContextMenu.cpp
                                                            KsAdvFilteringDialog.cpp)

    target_link_libraries(kshark-gui kshark-plot
                                     Qt5::Widgets
                                     Qt5::Network
                                     ${TRACEEVENT_LIBRARY}
                                     ${TRACECMD_LIBRARY}
                                     ${TRACEFS_LIBRARY}
                                     ${CMAKE_DL_LIBS})

    set_target_properties(kshark-gui PROPERTIES  SUFFIX ".so.${KS_VERSION_STRING}")

    message(STATUS ${KS_APP_NAME})
    add_executable(${KS_APP_NAME}          kernelshark.cpp)
    target_link_libraries(${KS_APP_NAME}   kshark-gui)

    message(STATUS "kshark-record")
    add_executable(kshark-record        kshark-record.cpp)
    target_link_libraries(kshark-record kshark-gui)

    install(TARGETS ${KS_APP_NAME} kshark-record kshark-gui
            RUNTIME DESTINATION ${_INSTALL_PREFIX}/bin/
            LIBRARY DESTINATION ${_INSTALL_PREFIX}/lib/${KS_APP_NAME}/)

    install(FILES "${KS_DIR}/${KS_APP_NAME}.desktop"
            DESTINATION ${_INSTALL_PREFIX}/share/applications/)

    install(FILES "${KS_DIR}/icons/${KS_ICON}"
                  "${KS_DIR}/icons/${KS_ICON_FIN}"
            DESTINATION ${_INSTALL_PREFIX}/share/icons/${KS_APP_NAME})

    install(FILES "${KS_DIR}/org.freedesktop.kshark-record.policy"
            DESTINATION /usr/share/polkit-1/actions/)

    install(PROGRAMS "${KS_DIR}/bin/kshark-su-record"
            DESTINATION ${_INSTALL_PREFIX}/bin/)

    add_subdirectory(plugins)

endif (Qt5Widgets_FOUND AND Qt5Network_FOUND AND NOT _LIBS)

find_program(DO_AS_ROOT pkexec)

configure_file( ${KS_DIR}/build/deff.h.cmake
                ${KS_DIR}/src/KsCmakeDef.hpp)
