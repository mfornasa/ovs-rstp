/*
 * Copyright (c) 2011-2014 M3S, Srl - Italy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Rapid Spanning Tree Protocol (IEEE 802.1D-2004) state machines
 * implementation (header file).
 *
 * Authors:
 *         Martino Fornasa <mf@fornasa.it>
 *         Daniele Venturino <daniele.venturino@m3s.it>
 *
 * References to IEEE 802.1D-2004 standard are enclosed in square brackets.
 * E.g. [17.3], [Table 17-1], etc.
 *
 */

#ifndef RSTP_STATE_MACHINES_H
#define RSTP_STATE_MACHINES_H 1

#include "rstp-common.h"

enum portFlag {
    PORT_UNKN = 0,
    PORT_ALT_BACK = 1,
    PORT_ROOT = 2,
    PORT_DES = 3
} portFlag_t;

/* Per-Bridge State Machine */
int port_role_selection_sm(struct rstp *);

/* Per-Port State Machines */
int port_receive_sm(struct rstp_port *);
int port_protocol_migration_sm(struct rstp_port *);
int bridge_detection_sm(struct rstp_port *);
int port_transmit_sm(struct rstp_port *);
int port_information_sm(struct rstp_port *);
int port_role_transition_sm(struct rstp_port *);
int port_state_transition_sm(struct rstp_port *);
int topology_change_sm(struct rstp_port *);
/* port_timers_sm() not defined as a state machine */

/* Methods called by the Forwarding Layer, through functions of rstp.h. */
int move_rstp(struct rstp *);
void decrease_rstp_port_timers(struct rstp *);
int validate_received_bpdu(struct rstp_port *, const void *bpdu, size_t);
void process_received_bpdu(struct rstp_port *, const void *, size_t);

/* SM functions */
void updt_role_disabled_tree(struct rstp *);
void clear_reselect_tree(struct rstp *);
void updt_roles_tree(struct rstp *);
void set_selected_tree(struct rstp *);

void updt_bpdu_version(struct rstp_port *);
void record_agreement(struct rstp_port *);
void set_tc_flags(struct rstp_port *);
void record_dispute(struct rstp_port *);
void record_proposal(struct rstp_port *);
void record_priority(struct rstp_port *);
void record_times(struct rstp_port *);
void updt_rcvd_info_while(struct rstp_port *);
void time_encode(unsigned int, uint8_t *);
unsigned int time_decode(uint8_t *);
void tx_config(struct rstp_port *);
void tx_tcn(struct rstp_port *);
void tx_rstp(struct rstp_port *);
int rcv_info(struct rstp_port *);
int better_or_same_info(struct rstp_port *, int);
void set_re_root_tree(struct rstp_port *);
void set_sync_tree(struct rstp_port *);
int hello_time(struct rstp_port *);
int fwd_delay(struct rstp_port *);
int forward_delay(struct rstp_port *);
int edge_delay(struct rstp_port *);
int check_selected_role_change(struct rstp_port *, int);
int re_rooted(struct rstp_port *);
int all_synced(struct rstp *);
void enable_learning(struct rstp_port *);
void enable_forwarding(struct rstp_port *);
void disable_learning(struct rstp_port *);
void disable_forwarding(struct rstp_port *);
void new_tc_while(struct rstp_port *);
void set_tc_prop_tree(struct rstp_port *);
void set_tc_prop_bridge(struct rstp_port *);

#define NOT_SUPERIOR 0
#define SUPERIOR_ABSOLUTE 1
#define SUPERIOR_SAME_DES 2
#define SAME 3
int rstp_priority_vector_is_superior(struct rstp_priority_vector *v1,
                                     struct rstp_priority_vector *v2);

#endif /* rstp-state-machines.h */
