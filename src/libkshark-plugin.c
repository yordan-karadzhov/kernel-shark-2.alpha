// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    libkshark-plugin.c
 *  @brief   KernelShark plugins.
 */

// C
#ifndef _GNU_SOURCE
/** Use GNU C Library. */
#define _GNU_SOURCE

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>

// KernelShark
#include "libkshark-plugin.h"
#include "libkshark.h"

static struct kshark_event_handler *
gui_event_handler_alloc(int event_id, int sd,
			kshark_plugin_event_handler_func evt_func,
			kshark_plugin_draw_handler_func dw_func)
{
	struct kshark_event_handler *handler = malloc(sizeof(*handler));

	if (!handler) {
		fprintf(stderr,
			"failed to allocate memory for gui eventhandler");
		return NULL;
	}

	handler->next = NULL;
	handler->id = event_id;
	handler->sd = sd;
	handler->event_func = evt_func;
	handler->draw_func = dw_func;

	return handler;
}

/**
 * @brief Search the list of event handlers for a handle associated with a
 *	  given event type.
 *
 * @param handlers: Input location for the Event handler list.
 * @param event_id: Event Id to search for.
 * @param sd: Data stream identifier.
 */
struct kshark_event_handler *
kshark_find_event_handler(struct kshark_event_handler *handlers,
			  int event_id, int sd)
{
	for (; handlers; handlers = handlers->next)
		if (handlers->id == event_id && handlers->sd == sd)
			return handlers;

	return NULL;
}

/**
 * @brief Add new event handler to an existing list of handlers.
 *
 * @param handlers: Input location for the Event handler list.
 * @param event_id: Event Id.
 * @param sd: Data stream identifier.
 * @param evt_func: Input location for an Event action provided by the plugin.
 * @param dw_func: Input location for a Draw action provided by the plugin.
 *
 * @returns Zero on success, or a negative error code on failure.
 */
int kshark_register_event_handler(struct kshark_event_handler **handlers,
				  int event_id, int sd,
				  kshark_plugin_event_handler_func evt_func,
				  kshark_plugin_draw_handler_func dw_func)
{
	struct kshark_event_handler *handler =
		gui_event_handler_alloc(event_id, sd, evt_func, dw_func);
	printf("%i %i  kshark_event_handler: %p\n", event_id, sd, handler);

	if(!handler)
		return -ENOMEM;

	handler->next = *handlers;
	*handlers = handler;
	return 0;
}

/**
 * @brief Search the list for a specific plugin handle. If such a plugin handle
 *	  exists, unregister (remove and free) this handle from the list.
 *
 * @param handlers: Input location for the Event handler list.
 * @param event_id: Event Id of the plugin handler to be unregistered.
 * @param sd: Data stream identifier.
 * @param evt_func: Event action function of the handler to be unregistered.
 * @param dw_func: Draw action function of the handler to be unregistered.
 */
void kshark_unregister_event_handler(struct kshark_event_handler **handlers,
				     int event_id, int sd,
				     kshark_plugin_event_handler_func evt_func,
				     kshark_plugin_draw_handler_func dw_func)
{
	struct kshark_event_handler **last;

	for (last = handlers; *last; last = &(*last)->next) {
		if ((*last)->id == event_id &&
		    (*last)->sd == sd &&
		    (*last)->event_func == evt_func &&
		    (*last)->draw_func == dw_func) {
			struct kshark_event_handler *this_handler;
			this_handler = *last;
			*last = this_handler->next;
			free(this_handler);

			return;
		}
	}
}

/**
 * @brief Free all Event handlers in a given list.
 *
 * @param handlers: Input location for the Event handler list.
 */
void kshark_free_event_handler_list(struct kshark_event_handler *handlers)
{
	struct kshark_event_handler *last;

	while (handlers) {
		last = handlers;
		handlers = handlers->next;
		free(last);
	}
}

/**
 * @brief Allocate memory for a new plugin. Add this plugin to the list of
 *	  plugins used by the session.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param file: The plugin object file to load.
 *
 * @returns The plugin object on success, or NULL on failure.
 */
struct kshark_plugin_list *
kshark_register_plugin(struct kshark_context *kshark_ctx, const char *file)
{
	struct kshark_plugin_list *plugin = kshark_ctx->plugins;
	struct stat st;
	int ret;

	while (plugin) {
		if (strcmp(plugin->file, file) == 0)
			return NULL;

		plugin = plugin->next;
	}

	ret = stat(file, &st);
	if (ret < 0) {
		fprintf(stderr, "plugin %s not found\n", file);
		return NULL;
	}

	plugin = calloc(sizeof(struct kshark_plugin_list), 1);
	if (!plugin) {
		fprintf(stderr, "failed to allocate memory for plugin\n");
		return NULL;
	}

	plugin->streams = NULL;

	if (asprintf(&plugin->file, "%s", file) <= 0) {
		fprintf(stderr,
			"failed to allocate memory for plugin file name");
		return NULL;
	}

	plugin->handle = dlopen(plugin->file, RTLD_NOW | RTLD_GLOBAL);
	if (!plugin->handle)
		goto fail;

	plugin->init = dlsym(plugin->handle,
			     KSHARK_PLUGIN_INITIALIZER_NAME);

	plugin->close = dlsym(plugin->handle,
			      KSHARK_PLUGIN_DEINITIALIZER_NAME);

	if (!plugin->init || !plugin->close)
		goto fail;

	plugin->next = kshark_ctx->plugins;
	kshark_ctx->plugins = plugin;

	return plugin;

 fail:
	fprintf(stderr, "cannot load plugin '%s'\n%s\n",
		plugin->file, dlerror());

	if (plugin->handle) {
		dlclose(plugin->handle);
		plugin->handle = NULL;
	}

	free(plugin);

	return NULL;
}

/**
 * Clear the list of Data streams for which the plugin has to be applied.
 * This effectively makes the plugin idle.
 */
void kshark_reset_plugin_streams(struct kshark_plugin_list *plugin)
{
	struct kshark_stream_list *last_stream;

	while (plugin->streams) {
		last_stream = plugin->streams;
		plugin->streams = plugin->streams->next;
		free(last_stream);
	}
}

/** Close and free this plugin. */
static void free_plugin(struct kshark_plugin_list *plugin)
{
	dlclose(plugin->handle);
	kshark_reset_plugin_streams(plugin);
	free(plugin->file);
	free(plugin);
}

/**
 * @brief Unrgister a plugin.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param file: The plugin object file to unregister.
 */
void kshark_unregister_plugin(struct kshark_context *kshark_ctx,
			      const char *file)
{
	struct kshark_plugin_list **last;

	for (last = &kshark_ctx->plugins; *last; last = &(*last)->next) {
		if (strcmp((*last)->file, file) == 0) {
			struct kshark_plugin_list *this_plugin;
			this_plugin = *last;
			*last = this_plugin->next;

			free_plugin(this_plugin);

			return;
		}
	}
}

/**
 * @brief Free all plugins in a given list.
 *
 * @param plugins: Input location for the plugins list.
 */
void kshark_free_plugin_list(struct kshark_plugin_list *plugins)
{
	struct kshark_plugin_list *last;

	while (plugins) {
		last = plugins;
		plugins = plugins->next;

		free_plugin(last);
	}
}

/**
 * @brief Find a plugin by its object file name.
 *
 * @param plugins: A list of plugins to search in.
 * @param file: The plugin object file to load.
 *
 * @returns The plugin object on success, or NULL on failure.
 */
struct kshark_plugin_list *
kshark_find_plugin(struct kshark_plugin_list *plugins, const char *file)
{
	for (; plugins; plugins = plugins->next)
		if (strcmp(plugins->file, file) == 0)
			return plugins;

	return NULL;
}

/**
 * @brief Add Data streams the list of streams for which the plugin has to
 *	  be applied.
 *
 * @param plugin: The plugin to which the stream will be added.
 * @param sd: Data stream identifier.
 */
void kshark_plugin_add_stream(struct kshark_plugin_list *plugin, int sd)
{
	struct kshark_stream_list *stream;

	/* First make sure that the Data Stream has not been added already. */
	for (stream = plugin->streams; stream; stream = stream->next)
		if (stream->stream_id == sd)
			return;

	/* Add the stream to the list. */
	stream = malloc(sizeof(*stream));
	stream->stream_id = sd;
	stream->next = plugin->streams;
	plugin->streams = stream;
}

/**
 * @brief Remove Data streams the list of streams for which the plugin has to
 *	  be applied.
 *
 * @param plugin: The plugin from which the stream will be removed.
 * @param sd: Data stream identifier.
 */
void kshark_plugin_remove_stream(struct kshark_plugin_list *plugin, int sd)
{
	struct kshark_stream_list **stream;

	for (stream = &plugin->streams; *stream; stream = &(*stream)->next) {
		if ((*stream)->stream_id == sd) {
			struct kshark_stream_list *this_stream;

			this_stream = *stream;
			*stream = this_stream->next;
			free(this_stream);
		}
	}
}

/**
 * @brief Use this function to initialize/update/deinitialize a plugin for
 *	  a given Data stream.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param plugin: The plugin to be handled.
 * @param sd: Data stream identifier.
 * @param task_id: Action identifier specifying the action to be executed.
 *
 * @returns The number of successful added/removed plugin handlers on success,
 *	    or a negative error code on failure.
 */
int kshark_handle_plugin(struct kshark_context *kshark_ctx,
			 struct kshark_plugin_list *plugin,
			 int sd,
			 enum kshark_plugin_actions task_id)
{
	struct kshark_stream_list *stream;
	int handler_count = 0;

	for (stream = plugin->streams; stream; stream = stream->next) {
		if (stream->stream_id == sd)
			switch (task_id) {
			case KSHARK_PLUGIN_INIT:
				handler_count = plugin->init(kshark_ctx, sd);
				break;

			case KSHARK_PLUGIN_UPDATE:
				plugin->close(kshark_ctx, sd);
				handler_count = plugin->init(kshark_ctx, sd);
				break;

			case KSHARK_PLUGIN_CLOSE:
				handler_count = plugin->close(kshark_ctx, sd);
				break;

			default:
				return -EINVAL;
			}
	}

	return handler_count;
}

/**
 * @brief Use this function to initialize/update/deinitialize all registered
 *	  plugins for a given Data stream.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param sd: Data stream identifier.
 * @param task_id: Action identifier specifying the action to be executed.
 *
 * @returns The number of successful added/removed plugin handlers on success,
 *	    or a negative error code on failure.
 */
int kshark_handle_all_plugins(struct kshark_context *kshark_ctx, int sd,
			      enum kshark_plugin_actions task_id)
{
	struct kshark_plugin_list *plugin;
	int handler_count = 0;

	for (plugin = kshark_ctx->plugins; plugin; plugin = plugin->next) {
		handler_count +=
			kshark_handle_plugin(kshark_ctx, plugin, sd, task_id);
	}

	return handler_count;
}

/** Close all registered plugins. */
void kshark_close_all_plugins(struct kshark_context *kshark_ctx)
{
	struct kshark_plugin_list *plugins = kshark_ctx->plugins;
	int i, *stream_ids = kshark_all_streams(kshark_ctx);

	for (i = 0; i < kshark_ctx->n_streams; ++i)
		kshark_handle_all_plugins(kshark_ctx, stream_ids[i],
					  KSHARK_PLUGIN_CLOSE);

	while (plugins) {
		kshark_reset_plugin_streams(plugins);
		plugins = plugins->next;
	}

	free(stream_ids);
}
