// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2020 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    event_field_plot.c
 *  @brief   .
 */

// C
#include <stdio.h>
#include <assert.h>
#include <limits.h>

// KernelShark
#include "plugins/event_field_plot.h"

/** Plugin context instance. */
static struct plugin_efp_context *
plugin_efp_context_handler[KS_MAX_NUM_STREAMS] = {NULL};

/** Get the per stream context of the plugin. */
struct plugin_efp_context *get_efp_context(int sd)
{
	return plugin_efp_context_handler[sd];
}

static void plugin_efp_free_context(int sd)
{
	struct plugin_efp_context *plugin_ctx = get_efp_context(sd);
	if (!plugin_ctx)
		return;

	free(plugin_ctx->event_name);
	free(plugin_ctx->field_name);

	if (plugin_ctx->data)
		kshark_free_data_container(plugin_ctx->data);

	plugin_efp_context_handler[sd] = NULL;
}

static struct plugin_efp_context *
plugin_efp_init_context(struct kshark_data_stream *stream)
{
	struct plugin_efp_context *plugin_ctx;
	int sd = stream->stream_id;

	/* No context should exist when we initialize the plugin. */
	assert(plugin_efp_context_handler[sd] == NULL);

	plugin_efp_context_handler[sd] = plugin_ctx =
		calloc(1, sizeof(*plugin_ctx));
	if (!plugin_ctx) {
		fprintf(stderr,
			"Failed to allocate memory for plugin event_field_plot.\n");
		return NULL;
	}

	plugin_set_event_name(plugin_ctx);
	plugin_set_field_name(plugin_ctx);
	plugin_set_select_condition(plugin_ctx);

	plugin_ctx->field_max = INT64_MIN;
	plugin_ctx->field_min = INT64_MAX;

	plugin_ctx->event_id = 
		stream->interface.find_event_id(stream, plugin_ctx->event_name);

	if (plugin_ctx->event_id < 0) {
		fprintf(stderr, "Event %s not found in stream %s\n",
			plugin_ctx->event_name, stream->file);
		goto fail;
	}

	plugin_ctx->data = kshark_init_data_container();
	if (!plugin_ctx->data)
		goto fail;

	return plugin_ctx;

 fail:
	plugin_efp_free_context(sd);
	return NULL;
}

static void plugin_get_field(struct kshark_data_stream *stream, void *rec,
			     struct kshark_entry *entry)
{
	struct plugin_efp_context *plugin_ctx;
	int64_t val;

	plugin_ctx = get_efp_context(stream->stream_id);
	if (!plugin_ctx)
		return;

	stream->interface.read_record_field_int64(stream, rec,
						  plugin_ctx->field_name,
						  &val);

	kshark_data_container_append(plugin_ctx->data, entry, val);

	if (val > plugin_ctx->field_max)
		plugin_ctx->field_max = val;

	if (val < plugin_ctx->field_min)
		plugin_ctx->field_min = val;
}

/** Load this plugin. */
int KSHARK_PLOT_PLUGIN_INITIALIZER(struct kshark_data_stream *stream)
{
	struct plugin_efp_context *plugin_ctx = plugin_efp_init_context(stream);
	printf("--> event_field init %i \n", stream->stream_id);
	if (!plugin_ctx)
		return 0;

	kshark_register_event_handler(stream,
				      plugin_ctx->event_id,
				      plugin_get_field);

	kshark_register_draw_handler(stream, draw_event_field);

	return 1;
}

/** Unload this plugin. */
int KSHARK_PLOT_PLUGIN_DEINITIALIZER(struct kshark_data_stream *stream)
{
	struct plugin_efp_context *plugin_ctx;
	int sd = stream->stream_id;

	printf("<-- event_field close %i\n", sd);
	plugin_ctx = get_efp_context(sd);
	if (!plugin_ctx)
		return 0;

	kshark_unregister_event_handler(stream,
					plugin_ctx->event_id,
					plugin_get_field);

	kshark_unregister_draw_handler(stream, draw_event_field);

	plugin_efp_free_context(sd);

	return 1;
}

void *KSHARK_MENU_PLUGIN_INITIALIZER(void *gui_ptr)
{
	printf("--> event_field init menu\n");
	return plugin_efp_add_menu(gui_ptr);
}
