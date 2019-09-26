/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <y.karadz@gmail.com>
 */

/**
 *  @file    sched_events.h
 *  @brief   Plugin for Sched events.
 */

#ifndef _KS_PLUGIN_SHED_H
#define _KS_PLUGIN_SHED_H

// KernelShark
#include "libkshark.h"
#include "libkshark-plugin.h"

#ifdef __cplusplus
extern "C" {
#endif

struct kshark_hash_id *get_second_pass_hash(int sd);

struct kshark_entry_collection *get_collections(int sd);

bool plugin_wakeup_match_rec_pid(struct kshark_context *kshark_ctx,
				 struct kshark_entry *e, int sd, int *pid);

bool plugin_switch_match_rec_pid(struct kshark_context *kshark_ctx,
				 struct kshark_entry *e, int sd, int *pid);

bool plugin_switch_match_entry_pid(struct kshark_context *kshark_ctx,
				   struct kshark_entry *e,
				   int sd, int *pid);

bool plugin_match_pid(struct kshark_context *kshark_ctx,
		      struct kshark_entry *e, int sd, int *pid);

void plugin_draw(struct kshark_cpp_argv *argv, int sd, int pid,
		 int draw_action);

#ifdef __cplusplus
}
#endif

#endif
