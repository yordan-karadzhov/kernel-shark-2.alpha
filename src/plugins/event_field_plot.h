/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2020 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    event_field_plot.h
 *  @brief   
 */

#ifndef _KS_PLUGIN_EVENT_FIELD_H
#define _KS_PLUGIN_EVENT_FIELD_H

// KernelShark
#include "libkshark.h"
#include "libkshark-plugin.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef bool (*val_select_func) (unsigned long long,
				 unsigned long long);

/** Structure representing a plugin-specific context. */
struct plugin_efp_context {
	/** Trace event name. */
	char 		*event_name;

	/** Event field name. */
	char 		*field_name;

	/** The max value of the field in the data. */
	int64_t		field_max;

	/** The min value of the field in the data. */
	int64_t		field_min;

	/** Trace event identifier. */
	int		event_id;

	/** . */
	bool		show_max;

	/** . */
	val_select_func		condition;

	/** . */
	struct kshark_data_container	*data;
};

struct plugin_efp_context *get_efp_context(int sd);

void draw_event_field(struct kshark_cpp_argv *argv_c,
		      int sd, int pid, int draw_action);

void *plugin_efp_add_menu(void *gui_ptr);

void plugin_set_event_name(struct plugin_efp_context *plugin_ctx);

void plugin_set_field_name(struct plugin_efp_context *plugin_ctx);

void plugin_set_select_condition(struct plugin_efp_context *plugin_ctx);

#ifdef __cplusplus
}
#endif

#endif
