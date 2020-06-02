/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
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

/** Structure representing a plugin-specific context. */
struct plugin_sched_context {
	/** Page event used to parse the page. */
	struct tep_handle	*tep;

	/** Pointer to the sched_switch_event object. */
	struct tep_event	*sched_switch_event;

	/** Pointer to the sched_switch_next_field format descriptor. */
	struct tep_format_field	*sched_switch_next_field;

	/** Pointer to the sched_switch_comm_field format descriptor. */
	struct tep_format_field	*sched_switch_comm_field;

	/** Pointer to the sched_switch_prev_state_field format descriptor. */
	struct tep_format_field	*sched_switch_prev_state_field;

	/** Pointer to the sched_waking_event object. */
	struct tep_event        *sched_waking_event;

	/** Pointer to the sched_waking_pid_field format descriptor. */
	struct tep_format_field *sched_waking_pid_field;

	/** True if the second pass is already done. */
	bool	second_pass_done;

	/** . */
	struct kshark_data_container	*ss_data;

	/** . */
	struct kshark_data_container	*sw_data;
};

struct plugin_sched_context *get_sched_context(int sd);

typedef int64_t ks_num_field_t;

int plugin_sched_get_pid(ks_num_field_t field);

int plugin_sched_get_prev_state(ks_num_field_t field);

void plugin_draw(struct kshark_cpp_argv *argv, int sd, int pid,
		 int draw_action);

#ifdef __cplusplus
}
#endif

#endif
