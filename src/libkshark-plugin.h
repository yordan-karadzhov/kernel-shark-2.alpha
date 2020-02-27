/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2016 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 */

/**
 *  @file    libkshark-plugin.h
 *  @brief   KernelShark plugins.
 */

#ifndef _KSHARK_PLUGIN_H
#define _KSHARK_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// C
#include <stdint.h>
#include <stdbool.h>

/* Quiet warnings over documenting simple structures */
//! @cond Doxygen_Suppress

#define _MAKE_STR(x)	#x

#define MAKE_STR(x)	_MAKE_STR(x)

#define KSHARK_PLOT_PLUGIN_INITIALIZER kshark_data_plugin_initializer

#define KSHARK_PLOT_PLUGIN_DEINITIALIZER kshark_data_plugin_deinitializer

#define KSHARK_PLOT_PLUGIN_INITIALIZER_NAME MAKE_STR(KSHARK_PLOT_PLUGIN_INITIALIZER)

#define KSHARK_PLOT_PLUGIN_DEINITIALIZER_NAME MAKE_STR(KSHARK_PLOT_PLUGIN_DEINITIALIZER)

#define KSHARK_MENU_PLUGIN_INITIALIZER kshark_plugin_menu_initializer

#define KSHARK_MENU_PLUGIN_INITIALIZER_NAME MAKE_STR(KSHARK_MENU_PLUGIN_INITIALIZER)

#define KSHARK_INPUT_INITIALIZER kshark_input_initializer

#define KSHARK_INPUT_DEINITIALIZER kshark_input_deinitializer

#define KSHARK_INPUT_CHECK kshark_input_check

#define KSHARK_INPUT_INITIALIZER_NAME MAKE_STR(KSHARK_INPUT_INITIALIZER)

#define KSHARK_INPUT_DEINITIALIZER_NAME MAKE_STR(KSHARK_INPUT_DEINITIALIZER)

#define KSHARK_INPUT_CHECK_NAME MAKE_STR(KSHARK_INPUT_CHECK)

struct kshark_data_stream;
struct kshark_context;
struct kshark_entry;

//! @endcond

struct kshark_trace_histo;

/**
 * Structure representing the C arguments of the drawing function of
 * a plugin.
 */
struct kshark_cpp_argv {
	/** Pointer to the model descriptor object. */
	struct kshark_trace_histo	*histo;
};

/** A function type to be used when defining plugin functions for drawing. */
typedef void (*kshark_plugin_draw_handler_func)(struct kshark_cpp_argv *argv,
						int sd,
						int val,
						int draw_action);

/**
 * A function type to be used when defining plugin functions for data
 * manipulation.
 */
typedef void (*kshark_plugin_event_handler_func)(struct kshark_data_stream *stream,
						 void *rec, struct kshark_entry *e);

/** Plugin action identifier. */
enum kshark_plugin_actions {
	/**
	 * Load plugins action. This action identifier is used when handling
	 * plugins.
	 */
	KSHARK_PLUGIN_INIT,

	/**
	 * Reload plugins action. This action identifier is used when handling
	 * plugins.
	 */
	KSHARK_PLUGIN_UPDATE,

	/**
	 * Unload plugins action. This action identifier is used when handling
	 * plugins.
	 */
	KSHARK_PLUGIN_CLOSE,
};

/** No event identifier associated with the plugin. */
#define KS_PLUGIN_NO_EVENT (-ENODEV)

/*** Plugin's Trace Event processing handler structure. */
struct kshark_event_proc_handler {
	/** Pointer to the next Plugin Event handler. */
	struct kshark_event_proc_handler		*next;

	/**
	 * Event action function. This action can be used to modify the content
	 * of all kshark_entries having Event Ids equal to "id".
	 */
	kshark_plugin_event_handler_func	event_func;

	/** Unique Id ot the trace event type. */
	int id;
};

struct kshark_event_proc_handler *
kshark_find_event_handler(struct kshark_event_proc_handler *handlers, int event_id);

int kshark_register_event_handler(struct kshark_data_stream *stream,
				  int event_id,
				  kshark_plugin_event_handler_func evt_func);

void kshark_unregister_event_handler(struct kshark_data_stream *stream,
				     int event_id,
				     kshark_plugin_event_handler_func evt_func);

void kshark_free_event_handler_list(struct kshark_event_proc_handler *handlers);

/*** Plugin's drawing handler structure. */
struct kshark_draw_handler {
	/** Pointer to the next Plugin Event handler. */
	struct kshark_draw_handler		*next;

	/**
	 * Draw action function. This action can be used to draw additional
	 * graphical elements (shapes) for all kshark_entries having Event Ids
	 * equal to "id".
	 */
	kshark_plugin_draw_handler_func		draw_func;
};

int kshark_register_draw_handler(struct kshark_data_stream *stream,
				 kshark_plugin_draw_handler_func draw_func);

void kshark_unregister_draw_handler(struct kshark_data_stream *stream,
				    kshark_plugin_draw_handler_func draw_func);

void kshark_free_draw_handler_list(struct kshark_draw_handler *handlers);

/**
 * A function type to be used when defining load/reload/unload plugin
 * functions.
 */
typedef int (*kshark_plugin_load_func)(struct kshark_data_stream *);

typedef int (*kshark_check_data_func)(const char *filename);

typedef void (*kshark_plugin_ctrl_func)(void *);


/** Plugable Data Readout Interface (dpi). */
struct kshark_dri {
	/** The a short name for this data input. */
	char				*name;

	/** Data format identifier. */
	int				format;

	/** Callback function for initialization of the data input. */
	kshark_plugin_load_func		init;

	/** Callback function for deinitialization of the data input. */
	kshark_plugin_load_func		close;

	/**
	 * Callback function for checking if the data input is applicable for
	 * a given data file.
	 */
	kshark_check_data_func		check_data;
};

/** Linked list of Data Readout Interfaces (dri). */
struct kshark_dri_list {
	/** Pointer to the next input interface. */
	struct kshark_dri_list		*next;

	/** Pointer to the interface of methods used by the input. */
	struct kshark_dri		*interface;
};

/** Plugable Data Processing Interface (dpi). */
struct kshark_dpi {
	/** The plugin's short name. */
	char				*name;

	/** Callback function for initialization of the plugin. */
	kshark_plugin_load_func		init;

	/** Callback function for deinitialization of the plugin. */
	kshark_plugin_load_func		close;
};

/** Linked list of data processing interfaces (dpi). */
struct kshark_dpi_list {
	/** Pointer to the next plugin interface. */
	struct kshark_dpi_list		*next;

	/** Pointer to the interface of methods used by the plugin. */
	struct kshark_dpi		*interface;

	/**
	 * The status of the interface.
	 */
	int				status;
};

struct kshark_dri_list *
kshark_register_input(struct kshark_context *kshark_ctx,
		      struct kshark_dri *plugin);

void kshark_unregister_input(struct kshark_context *kshark_ctx,
			     const char *file);

void kshark_free_dri_list(struct kshark_dri_list *inputs);

/** Linked list of plugins. */
struct kshark_plugin_list {
	/** Pointer to the next plugin. */
	struct kshark_plugin_list	*next;

	/** The plugin's short name. */
	char	*name;

	/** The plugin object file to load. */
	char	*file;

	/** Plugin's object file handler. */
	void	*handle;

	/**
	 * Control interface of the plugin. Can be used to configure
	 * the plugin.
	 */
	kshark_plugin_ctrl_func		ctrl_interface;

	/** The interface of methods used by a data processing plugin. */
	struct kshark_dpi		*process_interface;

	/** The interface of methods used by a data readout plugin. */
	struct kshark_dri		*readout_interface;
};

/** Plugin status identifiers. */
enum kshark_plugin_status {
	/** The plugin is enabled. */
	KSHARK_PLUGIN_ENABLED	= 1 << 0,

	/** The plugin is successfully loaded. */
	KSHARK_PLUGIN_LOADED	= 1 << 1,

	/** The plugin failed to initialization. */
	KSHARK_PLUGIN_FAILED	= 1 << 2,
};

struct kshark_plugin_list *
kshark_register_plugin(struct kshark_context *kshark_ctx,
		       const char *name,
		       const char *file);

void kshark_unregister_plugin(struct kshark_context *kshark_ctx,
			      const char *name,
			      const char *file);

void kshark_free_plugin_list(struct kshark_plugin_list *plugins);

void kshark_free_dpi_list(struct kshark_dpi_list *plugins);

struct kshark_plugin_list *
kshark_find_plugin(struct kshark_plugin_list *plugins, const char *file);

struct kshark_plugin_list *
kshark_find_plugin_by_name(struct kshark_plugin_list *plugins,
			   const char *name);

struct kshark_dpi_list *
kshark_register_plugin_to_stream(struct kshark_data_stream *stream,
				 struct kshark_dpi *plugin,
				 bool active);

void kshark_unregister_plugin_from_stream(struct kshark_data_stream *stream,
					  struct kshark_dpi *plugin);

int kshark_handle_dpi(struct kshark_data_stream *stream,
		      struct kshark_dpi_list *plugin,
		      enum kshark_plugin_actions task_id);

int kshark_handle_all_dpis(struct kshark_data_stream *stream,
			   enum kshark_plugin_actions  task_id);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _KSHARK_PLUGIN_H
