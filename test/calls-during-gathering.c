/**
 * Copyright (c) 2026 Apple Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// Calls into an agent while juice_gather_candidates() is starting, as an application does when
// signaling runs on its own thread. Each scenario runs in poll, mux and thread modes and must end
// with both agents connected:
// - while gathering waits in the GATHERING callback, from another thread and from the callback:
//   setting the remote description, gathering again (which must do nothing), and calling setters
//   which must be called before gathering (which must fail)
// - concurrent: gathering and setting the remote description start together, repeatedly
// - trickle: gathering and adding remote candidates start together, repeatedly
// Finally, in poll mode only, the GATHERING callback calls into an agent whose callback calls back
// into the gathering agent, which must not deadlock.

#include "juice/juice.h"

#include "thread.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(unsigned int ms) { Sleep(ms); }
#else
#include <unistd.h>
static void sleep_ms(unsigned int ms) { usleep(ms * 1000); }
#endif

// Relaxed accesses for a flag shared with another thread: they must not order the threads, as that
// would hide races from ThreadSanitizer
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#define load_relaxed(a) atomic_load_explicit(a, memory_order_relaxed)
#define store_relaxed(a, v) atomic_store_explicit(a, v, memory_order_relaxed)
#else
#define load_relaxed(a) atomic_load(a)
#define store_relaxed(a, v) atomic_store(a, v)
#endif

#define ITERATIONS 5
#define MAX_CANDIDATES 16

typedef enum { ACTION_SET_REMOTE, ACTION_GATHER_AGAIN, ACTION_SET_CONFIG } action_t;

typedef struct {
	juice_agent_t *agent; // agent 2, which gathers while being called into
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	char candidates[MAX_CANDIDATES][JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	int candidates_count;
	int agent_candidates_count; // candidates gathered by agent 2
	mutex_t mutex;              // protects the candidates and their counts
	action_t action;
	bool other_thread;
	bool triggered;
	thread_t thread;
	bool thread_started;
	atomic(bool) action_done;     // set by the other thread
	bool action_done_in_callback; // the other thread was not blocked by the callback
	mutex_t gate;                 // held by the main thread until both threads may start
	int gather_result;
	int result;
} context_t;

// Collects the candidates of agent 1, which are passed to agent 2, and counts those of agent 2
static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	context_t *ctx = user_ptr;
	mutex_lock(&ctx->mutex);
	if (agent == ctx->agent) {
		++ctx->agent_candidates_count;
	} else if (ctx->candidates_count < MAX_CANDIDATES) {
		snprintf(ctx->candidates[ctx->candidates_count], JUICE_MAX_CANDIDATE_SDP_STRING_LEN, "%s",
		         sdp);
		++ctx->candidates_count;
	}
	mutex_unlock(&ctx->mutex);
}

static juice_agent_t *create_agent(juice_concurrency_mode_t mode, juice_cb_state_changed_t cb_state,
                                   juice_cb_candidate_t cb_candidate, void *user_ptr) {
	juice_config_t config;
	memset(&config, 0, sizeof(config));
	config.concurrency_mode = mode;
	config.bind_address = "127.0.0.1";
	config.cb_state_changed = cb_state;
	config.cb_candidate = cb_candidate;
	config.user_ptr = user_ptr;
	return juice_create(&config);
}

static bool is_connected(juice_agent_t *agent) {
	juice_state_t state = juice_get_state(agent);
	return state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED;
}

static bool wait_connected(juice_agent_t *agent1, juice_agent_t *agent2, const char *name) {
	for (int i = 0; i < 50 && !(is_connected(agent1) && is_connected(agent2)); ++i)
		sleep_ms(100);

	if (!is_connected(agent1) || !is_connected(agent2)) {
		printf("%s: agents did not connect: state 1 %s, state 2 %s\n", name,
		       juice_state_to_string(juice_get_state(agent1)),
		       juice_state_to_string(juice_get_state(agent2)));
		return false;
	}
	return true;
}

// Agent 1 gathers first; the context gets its description and candidates
static juice_agent_t *create_first_agent(juice_concurrency_mode_t mode, context_t *ctx,
                                         bool with_candidates) {
	// Agent 1 uses poll mode, as in test/mux.c
	if (mode == JUICE_CONCURRENCY_MODE_MUX)
		mode = JUICE_CONCURRENCY_MODE_POLL;

	juice_agent_t *agent1 = create_agent(mode, NULL, on_candidate, ctx);
	if (!agent1)
		return NULL;

	if (!with_candidates) // without candidates, they are passed separately
		juice_get_local_description(agent1, ctx->sdp, JUICE_MAX_SDP_STRING_LEN);

	if (juice_gather_candidates(agent1) < 0) { // host candidates only, done synchronously
		juice_destroy(agent1);
		return NULL;
	}

	if (with_candidates)
		juice_get_local_description(agent1, ctx->sdp, JUICE_MAX_SDP_STRING_LEN);

	return agent1;
}

static void set_remote_from(juice_agent_t *agent, juice_agent_t *from) {
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(from, sdp, JUICE_MAX_SDP_STRING_LEN);
	juice_set_remote_description(agent, sdp);
}

// Returns 0 if the action behaves as expected while gathering is starting
static int run_action(context_t *ctx) {
	switch (ctx->action) {
	case ACTION_SET_REMOTE:
		return juice_set_remote_description(ctx->agent, ctx->sdp);

	case ACTION_GATHER_AGAIN:
		return juice_gather_candidates(ctx->agent); // must do nothing

	case ACTION_SET_CONFIG: {
		juice_turn_server_t turn_server;
		memset(&turn_server, 0, sizeof(turn_server));
		turn_server.host = "127.0.0.1";
		turn_server.username = "username";
		turn_server.password = "password";
		turn_server.port = 3478;
		bool failed =
		    juice_set_local_ice_attributes(ctx->agent, "abcd", "0123456789012345678901") < 0 &&
		    juice_add_turn_server(ctx->agent, &turn_server) < 0 &&
		    juice_set_ice_tcp_mode(ctx->agent, JUICE_ICE_TCP_MODE_ACTIVE) < 0;
		return failed ? 0 : -1;
	}

	default:
		return -1;
	}
}

static thread_return_t THREAD_CALL action_entry(void *arg) {
	context_t *ctx = arg;
	ctx->result = run_action(ctx); // read after joining
	store_relaxed(&ctx->action_done, true);
	return (thread_return_t)0;
}

static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	(void)agent;
	context_t *ctx = user_ptr;
	if (state != JUICE_STATE_GATHERING || ctx->triggered)
		return;

	// We are inside juice_gather_candidates(), before the connection is created
	ctx->triggered = true;
	if (!ctx->other_thread) {
		ctx->result = run_action(ctx);
		return;
	}

	ctx->thread_started = thread_init(&ctx->thread, action_entry, ctx) == 0;

	// Let the other thread call in before the connection is created. It must not be blocked
	// until the callback returns; don't join it, so that a blocked thread fails rather than hangs.
	for (int i = 0; i < 200 && ctx->thread_started; ++i) {
		if (load_relaxed(&ctx->action_done)) {
			ctx->action_done_in_callback = true;
			break;
		}
		sleep_ms(10);
	}
}

static bool test_callback(juice_concurrency_mode_t mode, action_t action, bool other_thread,
                          const char *name) {
	context_t ctx;
	memset(&ctx, 0, sizeof(ctx));
	mutex_init(&ctx.mutex, 0);
	store_relaxed(&ctx.action_done, false);
	ctx.action = action;
	ctx.other_thread = other_thread;
	ctx.result = -1;

	juice_agent_t *agent1 = create_first_agent(mode, &ctx, true);
	juice_agent_t *agent2 = create_agent(mode, on_state_changed2, on_candidate, &ctx);
	ctx.agent = agent2;
	bool success = agent1 && agent2 && juice_gather_candidates(agent2) == 0;
	if (ctx.thread_started)
		thread_join(ctx.thread, NULL);

	if (!success) {
		printf("%s: gathering failed\n", name);
	} else if (!ctx.triggered) {
		printf("%s: no GATHERING callback\n", name);
		success = false;
	} else if (other_thread && !ctx.thread_started) {
		printf("%s: thread creation failed\n", name);
		success = false;
	} else if (other_thread && !ctx.action_done_in_callback) {
		printf("%s: the other thread was blocked during the GATHERING callback\n", name);
		success = false;
	} else if (ctx.result != 0) {
		printf("%s: unexpected result %d during gathering\n", name, ctx.result);
		success = false;
	} else if (ctx.agent_candidates_count != 1) {
		printf("%s: agent 2 gathered %d candidates instead of 1\n", name,
		       ctx.agent_candidates_count);
		success = false;
	}

	if (success && action != ACTION_SET_REMOTE &&
	    juice_set_remote_description(agent2, ctx.sdp) < 0) {
		printf("%s: failed to set the remote description\n", name);
		success = false;
	}

	if (success) {
		set_remote_from(agent1, agent2);
		success = wait_connected(agent1, agent2, name);
	}

	juice_destroy(agent1);
	juice_destroy(agent2);
	mutex_destroy(&ctx.mutex);
	return success;
}

static thread_return_t THREAD_CALL set_remote_entry(void *arg) {
	context_t *ctx = arg;
	mutex_lock(&ctx->gate);
	mutex_unlock(&ctx->gate);
	ctx->result = juice_set_remote_description(ctx->agent, ctx->sdp);
	return (thread_return_t)0;
}

static thread_return_t THREAD_CALL gather_entry(void *arg) {
	context_t *ctx = arg;
	mutex_lock(&ctx->gate);
	mutex_unlock(&ctx->gate);
	ctx->gather_result = juice_gather_candidates(ctx->agent);
	return (thread_return_t)0;
}

static thread_return_t THREAD_CALL add_candidates_entry(void *arg) {
	context_t *ctx = arg;
	mutex_lock(&ctx->gate);
	mutex_unlock(&ctx->gate);
	int result = 0;
	for (int i = 0; i < ctx->candidates_count; ++i)
		if (juice_add_remote_candidate(ctx->agent, ctx->candidates[i]) < 0)
			result = -1;
	if (juice_set_remote_gathering_done(ctx->agent) < 0)
		result = -1;
	ctx->result = result;
	return (thread_return_t)0;
}

static bool test_concurrent(juice_concurrency_mode_t mode, bool trickle, const char *name) {
	bool success = true;
	for (int i = 0; i < ITERATIONS && success; ++i) {
		context_t ctx;
		memset(&ctx, 0, sizeof(ctx));
		mutex_init(&ctx.mutex, 0);
		mutex_init(&ctx.gate, 0);
		ctx.gather_result = -1;
		ctx.result = -1;

		juice_agent_t *agent1 = create_first_agent(mode, &ctx, !trickle);
		juice_agent_t *agent2 = create_agent(mode, NULL, NULL, NULL);
		ctx.agent = agent2;
		bool setup_ok = agent1 && agent2;
		if (setup_ok && trickle) // the description comes first, the candidates during gathering
			setup_ok = juice_set_remote_description(agent2, ctx.sdp) == 0;

		// Start both threads at the same time
		bool gather_started = false, remote_started = false;
		thread_t gather_thread, remote_thread;
		if (setup_ok) {
			mutex_lock(&ctx.gate);
			gather_started = thread_init(&gather_thread, gather_entry, &ctx) == 0;
			remote_started =
			    gather_started &&
			    thread_init(&remote_thread, trickle ? add_candidates_entry : set_remote_entry,
			                &ctx) == 0;
			mutex_unlock(&ctx.gate);
			if (gather_started)
				thread_join(gather_thread, NULL);
			if (remote_started)
				thread_join(remote_thread, NULL);
		}

		if (!remote_started || ctx.gather_result != 0 || ctx.result != 0) {
			printf("%s: iteration %d failed\n", name, i);
			success = false;
		} else {
			set_remote_from(agent1, agent2);
			success = wait_connected(agent1, agent2, name);
		}

		juice_destroy(agent1);
		juice_destroy(agent2);
		mutex_destroy(&ctx.gate);
		mutex_destroy(&ctx.mutex);
	}
	return success;
}

typedef struct {
	juice_agent_t *agent1; // connected to agent 3
	juice_agent_t *agent2; // gathers
	mutex_t mutex;
	bool in_callback; // agent 1 is in its CONNECTED callback
	bool done;
	bool success;
} deadlock_context_t;

static bool deadlock_get(deadlock_context_t *ctx, bool *flag) {
	mutex_lock(&ctx->mutex);
	bool value = *flag;
	mutex_unlock(&ctx->mutex);
	return value;
}

static void deadlock_set(deadlock_context_t *ctx, bool *flag) {
	mutex_lock(&ctx->mutex);
	*flag = true;
	mutex_unlock(&ctx->mutex);
}

// Called on the poll thread, which holds the registry lock while calling back
static void on_state_changed_deadlock1(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	(void)agent;
	deadlock_context_t *ctx = user_ptr;
	if (state != JUICE_STATE_CONNECTED || deadlock_get(ctx, &ctx->in_callback))
		return;

	deadlock_set(ctx, &ctx->in_callback);
	sleep_ms(300); // let agent 2 start gathering
	juice_get_state(ctx->agent2);
}

static void on_state_changed_deadlock2(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	(void)agent;
	deadlock_context_t *ctx = user_ptr;
	if (state == JUICE_STATE_GATHERING)
		juice_get_state(ctx->agent1);
}

static thread_return_t THREAD_CALL deadlock_entry(void *arg) {
	deadlock_context_t *ctx = arg;
	juice_agent_t *agent3 = create_agent(JUICE_CONCURRENCY_MODE_POLL, NULL, NULL, NULL);
	if (ctx->agent1 && ctx->agent2 && agent3 && juice_gather_candidates(ctx->agent1) == 0 &&
	    juice_gather_candidates(agent3) == 0) {
		set_remote_from(agent3, ctx->agent1);
		set_remote_from(ctx->agent1, agent3);
		for (int i = 0; i < 500 && !deadlock_get(ctx, &ctx->in_callback); ++i)
			sleep_ms(10);

		// Agent 1 is in its callback: gathering calls into it, and it calls into agent 2
		ctx->success =
		    deadlock_get(ctx, &ctx->in_callback) && juice_gather_candidates(ctx->agent2) == 0;
	}
	juice_destroy(agent3);
	deadlock_set(ctx, &ctx->done);
	return (thread_return_t)0;
}

static bool test_deadlock(const char *name) {
	static deadlock_context_t ctx; // outlives the call if the threads are blocked
	memset(&ctx, 0, sizeof(ctx));
	mutex_init(&ctx.mutex, 0);
	ctx.agent1 = create_agent(JUICE_CONCURRENCY_MODE_POLL, on_state_changed_deadlock1, NULL, &ctx);
	ctx.agent2 = create_agent(JUICE_CONCURRENCY_MODE_POLL, on_state_changed_deadlock2, NULL, &ctx);

	thread_t thread;
	if (thread_init(&thread, deadlock_entry, &ctx)) {
		printf("%s: thread creation failed\n", name);
		juice_destroy(ctx.agent1);
		juice_destroy(ctx.agent2);
		mutex_destroy(&ctx.mutex);
		return false;
	}

	for (int i = 0; i < 100 && !deadlock_get(&ctx, &ctx.done); ++i)
		sleep_ms(100);

	if (!deadlock_get(&ctx, &ctx.done)) {
		// Leave everything as is, as the threads are blocked
		printf("%s: deadlock\n", name);
		return false;
	}

	thread_join(thread, NULL);
	if (!ctx.success)
		printf("%s: failed\n", name);

	juice_destroy(ctx.agent1);
	juice_destroy(ctx.agent2);
	mutex_destroy(&ctx.mutex);
	return ctx.success;
}

int test_calls_during_gathering(void) {
	// Logging takes a mutex, which would order the threads and hide races, so only log errors
	juice_set_log_level(JUICE_LOG_LEVEL_ERROR);

	const struct {
		juice_concurrency_mode_t mode;
		const char *name;
	} modes[3] = {{JUICE_CONCURRENCY_MODE_POLL, "poll"},
	              {JUICE_CONCURRENCY_MODE_MUX, "mux"},
	              {JUICE_CONCURRENCY_MODE_THREAD, "thread"}};

	const struct {
		action_t action;
		const char *name;
	} actions[3] = {{ACTION_SET_REMOTE, "remote description"},
	                {ACTION_GATHER_AGAIN, "gathering again"},
	                {ACTION_SET_CONFIG, "setters"}};

	bool success = true;
	for (int m = 0; m < 3; ++m) {
		char name[128];
		for (int a = 0; a < 3; ++a) {
			snprintf(name, sizeof(name), "%s mode, %s from another thread", modes[m].name,
			         actions[a].name);
			success &= test_callback(modes[m].mode, actions[a].action, true, name);
			snprintf(name, sizeof(name), "%s mode, %s from the callback", modes[m].name,
			         actions[a].name);
			success &= test_callback(modes[m].mode, actions[a].action, false, name);
		}
		snprintf(name, sizeof(name), "%s mode, concurrent", modes[m].name);
		success &= test_concurrent(modes[m].mode, false, name);
		snprintf(name, sizeof(name), "%s mode, trickle", modes[m].name);
		success &= test_concurrent(modes[m].mode, true, name);
	}

	success &= test_deadlock("poll mode, callbacks calling into each other");

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}
