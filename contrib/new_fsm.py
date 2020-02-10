#!/usr/bin/env python3
import jinja2
import sys

def as_tuple(str_or_tuple):
	if isinstance(str_or_tuple, str):
		return (str_or_tuple,)
	return tuple(str_or_tuple)

class State:
	def __init__(s, name, events, out_states, onenter=True):
		s.name = name
		s.const = name.upper()
		s.events = as_tuple(events)
		s.out_states = as_tuple(out_states)
		s.onenter = onenter

	def __eq__(s, name):
		return s.name == name

class Event:
	def __init__(s, name):
		s.name = name
		s.const = name.upper()

	def __eq__(s, name):
		return s.name == name

class FSM:
	def NAME(s, name):
		return '_'.join((s.fsm_name, name)).upper()

	def name(s, name):
		return '_'.join((s.fsm_name, name)).lower()

	def state_const(s, name):
		return s.NAME('ST_' + name)

	def event_const(s, name):
		return s.NAME('EV_' + name)

	def __init__(s, fsm_name, priv, states, head=''):
		s.head = head
		s.fsm_name = fsm_name
		s.priv = priv
		s.states = states
		first = True
		for state in s.states:
			state.const = s.state_const(state.name)

			out_state_class_insts = []
			if first:
				# allow initial transition to self to activate timeout
				state.out_states = [state.name] + list(state.out_states)
				first = False

			for out_state in state.out_states:
				if out_state in out_state_class_insts:
					continue
				out_state_class_insts.append(s.states[s.states.index(out_state)])
			state.out_states = out_state_class_insts

		s.events = []
		for state in s.states:
			state_event_class_insts = []
			for event in state.events:
				if event not in s.events:
					ev = Event(event)
					ev.const = s.event_const(event)
					s.events.append(ev)
				else:
					ev = s.events[s.events.index(event)]
				state_event_class_insts.append(ev)
			state.events = state_event_class_insts

	def to_c(s):
		template = jinja2.Template(
'''
{{head}}
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

enum {{fsm_name}}_fsm_state {
{% for state in states %}	{{state.const}},
{% endfor -%}
};

enum {{fsm_name}}_fsm_event {
{% for event in events %}	{{event.const}},
{% endfor -%}
};

static const struct value_string {{fsm_name}}_fsm_event_names[] = {
{% for event in events %}	OSMO_VALUE_STRING({{event.const}}),
{% endfor %}	{}
};

static struct osmo_fsm {{fsm_name}}_fsm;

struct osmo_tdef {{fsm_name}}_tdefs[] = {
// FIXME
{% for state in states %}	{ .T={{(-loop.index)}}, .default_val=5, .desc="{{fsm_name}} {{state.name}} timeout" },
{% endfor %}	{}
};

static const struct osmo_tdef_state_timeout {{fsm_name}}_fsm_timeouts[32] = {
// FIXME
{% for state in states %}	[{{state.const}}] = { .T={{(-loop.index)}} },
{% endfor -%}
};

#define {{fsm_name}}_fsm_state_chg(state) \\
	osmo_tdef_fsm_inst_state_chg(fi, state, \\
				     {{fsm_name}}_fsm_timeouts, \\
				     {{fsm_name}}_tdefs, \\
				     5)

struct {{priv}} *{{fsm_name}}_alloc(struct osmo_fsm_inst *parent_fi, uint32_t parent_event_term)
{
	struct {{priv}} *{{priv}};

	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc_child(&{{fsm_name}}_fsm, parent_fi, parent_event_term);
	OSMO_ASSERT(fi);

	{{priv}} = talloc(fi, struct {{priv}});
	OSMO_ASSERT({{priv}});
	fi->priv = {{priv}};
	*{{priv}} = (struct {{priv}}){
		.fi = fi,
	};

	/* Do a state change to activate timeout */
	osmo_fsm_inst_state_chg(fi, {{states[0].const}});

	return {{priv}};
}
{% for state in states %}
{%- if state.onenter %}
static void {{fsm_name}}_{{state.name}}_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	//struct {{priv}} *{{priv}} = fi->priv;
	// FIXME
}
{%  endif %}
static void {{fsm_name}}_{{state.name}}_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct {{priv}} *{{priv}} = fi->priv;

	switch (event) {
{% for event in state.events %}
	case {{event.const}}:
		// FIXME
		break;
{% endfor %}
	default:
		OSMO_ASSERT(false);
	}
}

static int {{fsm_name}}_{{state.name}}_timeout(struct osmo_fsm_inst *fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}
{% endfor %}
#define S(x)    (1 << (x))

static const struct osmo_fsm_state {{fsm_name}}_fsm_states[] = {
{% for state in states %}	[{{state.const}}] = {
		.name = "{{state.name}}",
		.in_event_mask = 0
{% for event in state.events %}			| S({{event.const}})
{% endfor %}			,
		.out_state_mask = 0
{% for out_state in state.out_states %}			| S({{out_state.const}})
{% endfor %}			,{% if state.onenter %}
		.onenter = {{fsm_name}}_{{state.name}}_onenter,{% endif %}
		.action = {{fsm_name}}_{{state.name}}_action,
	},
{% endfor -%}
};

static int {{fsm_name}}_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	//struct {{priv}} *{{priv}} = fi->priv;
	switch (fi->state) {
{% for state in states %}
	case {{state.const}}:
		return {{fsm_name}}_{{state.name}}_timeout(fi);
{% endfor %}
	default:
		/* Return 1 to terminate FSM instance, 0 to keep running */
		return 1;
	}
}

static void {{fsm_name}}_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	//struct {{priv}} *{{priv}} = fi->priv;
	// FIXME
}

static struct osmo_fsm {{fsm_name}}_fsm = {
	.name = "{{fsm_name}}",
	.states = {{fsm_name}}_fsm_states,
	.num_states = ARRAY_SIZE({{fsm_name}}_fsm_states),
	.log_subsys = DLGLOBAL, // FIXME
	.event_names = {{fsm_name}}_fsm_event_names,
	.timer_cb = {{fsm_name}}_fsm_timer_cb,
	.cleanup = {{fsm_name}}_fsm_cleanup,
};

static __attribute__((constructor)) void {{fsm_name}}_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&{{fsm_name}}_fsm) == 0);
}
''')

		return template.render(**vars(s))

fsm = FSM(head='#include <osmocom/hlr/proxy.h>',
	  fsm_name = 'proxy_mm',
	  priv = 'proxy_mm',
	  states = (
		    State('ready',
			  ('subscr_invalid', 'rx_gsup_lu', 'rx_gsup_sai', ),
			  ('wait_subscr_data', 'wait_gsup_isd_result', 'wait_auth_tuples',),
			  onenter=False,
			 ),
		    State('wait_subscr_data',
			  ('rx_subscr_data',),
			  ('wait_gsup_isd_result', 'ready'),
			 ),
		    State('wait_gsup_isd_result',
			  ('rx_gsup_isd_result',),
			  ('ready',),
			 ),
		    State('wait_auth_tuples',
			  ('rx_auth_tuples',),
			  ('ready',),
			 ),
		   )
	 )
with open('proxy_mm.c', 'w') as f:
	f.write(fsm.to_c())

all_home_events = ('home_hlr_resolved',
		   'rx_insert_subscriber_data_req', 'rx_update_location_result',
		   'rx_send_auth_info_result',
		   'check_tuples','confirm_lu',)
all_home_states = ('wait_home_hlr_resolved', 'wait_update_location_result', 'wait_send_auth_info_result', 'idle', 'clear',)
fsm = FSM(head='#include <osmocom/hlr/proxy.h>',
	  fsm_name = 'proxy_to_home',
	  priv = 'proxy_mm',
	  states = [State(state, all_home_events, all_home_states) for state in all_home_states],
	 )
with open('proxy_to_home.c', 'w') as f:
	f.write(fsm.to_c())
