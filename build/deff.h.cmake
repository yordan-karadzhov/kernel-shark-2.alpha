 /**
 *  \file    KsCmakeDef.hpp
 *  \brief   This File is generated by CMAKE
 */

/* ! -- Do Not Hand Edit - This File is generated by CMAKE -- ! */

#ifndef _KS_CONFIG_H
#define _KS_CONFIG_H

/** KernelShark Version number. */
#cmakedefine KS_VERSION_STRING "@KS_VERSION_STRING@"

/** KernelShark installation prefix path. */
#cmakedefine _INSTALL_PREFIX "@_INSTALL_PREFIX@"

/** KernelShark plugins installation prefix path. */
#cmakedefine KS_PLUGIN_INSTALL_PREFIX "@KS_PLUGIN_INSTALL_PREFIX@"

/** Location of the trace-cmd executable. */
#cmakedefine TRACECMD_EXECUTABLE "@TRACECMD_EXECUTABLE@"

/** "pkexec" executable. */
#cmakedefine DO_AS_ROOT "@DO_AS_ROOT@"

/** GLUT has been found. */
#cmakedefine GLUT_FOUND

#ifdef __cplusplus

	#include <QString>

	/**
	 * String containing semicolon-separated list of plugin names.
	 * The plugins to be loaded when KernelShark starts are tagged
	 * with "default".
	 */
	const QString plugins = "@PLUGINS@";

#endif /* __cplusplus */

#endif // _KS_CONFIG_H
