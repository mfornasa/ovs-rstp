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
 * implementation.
 *
 * Authors:
 *         Martino Fornasa <mf@fornasa.it>
 *         Daniele Venturino <daniele.venturino@m3s.it>
 *
 * References to IEEE 802.1D-2004 standard are enclosed in square brackets.
 * E.g. [17.3], [Table 17-1], etc.
 *
 */

#include <config.h>
#include "rstp.h"
#include "rstp-state-machines.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>
#include "byte-order.h"
#include "connectivity.h"
#include "ofpbuf.h"
#include "packets.h"
#include "seq.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(rstp_sm);

void decrement_timer(unsigned int *);
static void rstp_send_bpdu(struct rstp_port *, const void *, size_t)
    OVS_REQUIRES(mutex);

void
process_received_bpdu(struct rstp_port *p, const void *bpdu, size_t bpdu_size)
{
    struct rstp *rstp =  p->rstp;

    if (!p->port_enabled)
        return;
    if (p->rcvd_bpdu)
        return;

    if (validate_received_bpdu(p, bpdu, bpdu_size) == 0) {
        p->rcvd_bpdu = true;
        p->rx_rstp_bpdu_cnt++;

        memcpy(&p->received_bpdu_buffer, bpdu, sizeof(struct rstp_bpdu));

        rstp->changes = true;
        move_rstp(rstp);
    } else {
        VLOG_DBG("Bad BPDU received");
        p->error_count++;
    }
}

int
validate_received_bpdu(struct rstp_port *p, const void *bpdu, size_t bpdu_size)
{
    /* Validation of received BPDU, see [9.3.4]. */
    const struct rstp_bpdu *temp;
    
    temp = bpdu;
    if (bpdu_size < 4 || ntohs(temp->protocol_identifier) != 0) {
        return -1;
    } else {
        if (temp->bpdu_type == CONFIGURATION_BPDU && bpdu_size >= 35 && (time_decode(temp->message_age) <  time_decode(temp->max_age))) {
            if ((ntohll(temp->designated_bridge_id) != p->rstp->bridge_identifier) ||
                    ((ntohll(temp->designated_bridge_id) ==  p->rstp->bridge_identifier) &&
                     (ntohs(temp->designated_port_id) != p->port_id))) {
                return 0;
            }
            else {
                return -1;
            }
        } else if (temp->bpdu_type == TOPOLOGY_CHANGE_NOTIFICATION_BPDU) {
            return 0;
        } else if (temp->bpdu_type == RAPID_SPANNING_TREE_BPDU && bpdu_size >= 36) {
            return 0;
        }
        else {
            return -1;
        }
    }
}

/*
* move_rstp()
* This method is invoked to move the State Machines. The SMs  move only if the
* boolean 'changes' is true, meaning that something changed and the SMs need to
* work to process this change.
* The boolean 'changes' is set every time a SM modifies its state, a BPDU is
* received, a timer expires or port down event is detected. If a parameter is set by
* management, then 'changes' is set.
*/
#define MAX_RSTP_ITERATIONS 1000 /* safeguard */
int
move_rstp(struct rstp *rstp )
{
    int port_no, num_iterations;
    num_iterations = 0;
    
    while (rstp->changes == true && num_iterations < MAX_RSTP_ITERATIONS) {
        VLOG_DBG("%s: move_rstp()", rstp->name);
        rstp->changes = false;
        port_role_selection_sm(rstp);
        for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
            struct rstp_port *p = rstp_get_port(rstp, port_no);
            if (p->rstp_state != RSTP_DISABLED) {
                port_receive_sm(p);
                bridge_detection_sm(p);
                port_information_sm(p);
                port_role_transition_sm(p);
                port_state_transition_sm(p);
                topology_change_sm(p);
                port_transmit_sm(p);
                port_protocol_migration_sm(p);
            }
        }
        num_iterations++;
        seq_change(connectivity_seq_get());
    }
    if (num_iterations >= MAX_RSTP_ITERATIONS) {
        VLOG_ERR("%s: move_rstp() reached the iteration safeguard limit!", rstp->name);
    }
    return 0;
}

void decrease_rstp_port_timers(struct rstp *r)
{
    int port_no;
    
    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p = rstp_get_port(r, port_no);
        decrement_timer(&p->hello_when);
        decrement_timer(&p->tc_while);
        decrement_timer(&p->fd_while);
        decrement_timer(&p->rcvd_info_while);
        decrement_timer(&p->rr_while);
        decrement_timer(&p->rb_while);
        decrement_timer(&p->mdelay_while);
        decrement_timer(&p->edge_delay_while);
        decrement_timer(&p->tx_count);
        p->uptime+=1;
    }
    r->changes = true;
    move_rstp(r);
}

void
decrement_timer(unsigned int *timer)
{
    if (*timer != 0) {
        *timer -= 1;
    }
}

/* Bridge State Machine. */
/* [17.28] Port Role Selection state machine. */

void
updt_role_disabled_tree(struct rstp *r)
{
    int port_no;
    
    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p = rstp_get_port(r, port_no);
        p->selected_role = ROLE_DISABLED;
    }
}

void
clear_reselect_tree(struct rstp *r)
{
    int port_no;
    
    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p = rstp_get_port(r, port_no);
        p->reselect = false;
    }
}

void
updt_roles_tree(struct rstp *r)
{
    int port_no;
    int vsel;
    struct rstp_priority_vector best_vector, candidate_vector;
    
    vsel = -1;
    best_vector = r->bridge_priority;
    /* Letter c1) */
    r->root_times = r->bridge_times;
    /* Letters a) b) c) */
    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        uint32_t old_root_path_cost;
        unsigned int root_path_cost;
        struct rstp_port *p = rstp_get_port(r, port_no);
        if (p->info_is !=INFO_IS_RECEIVED) {
            continue;
        }
        /* [17.6] */
        candidate_vector = p->port_priority;
        candidate_vector.bridge_port_id = p->port_id;
        old_root_path_cost = candidate_vector.root_path_cost;
        root_path_cost = old_root_path_cost + p->port_path_cost;
        candidate_vector.root_path_cost = root_path_cost;

        if ((candidate_vector.designated_bridge_id & 0xFFFFFFFFFFFFFF) == (r->bridge_priority.designated_bridge_id & 0xFFFFFFFFFFFFFF)) {
            break;
        }
        if (rstp_priority_vector_is_superior(&candidate_vector, &best_vector) == SUPERIOR_ABSOLUTE ||
            rstp_priority_vector_is_superior(&candidate_vector, &best_vector) == SUPERIOR_SAME_DES) {
            best_vector = candidate_vector;
            r->root_times = p->port_times;
            r->root_times.message_age++;
            vsel = p->port_number;
        }
    }
    r->root_priority = best_vector;
    r->root_port_id = best_vector.bridge_port_id; 
    VLOG_DBG("%s: new Root is "RSTP_ID_FMT"", r->name, RSTP_ID_ARGS(r->root_priority.root_bridge_id));
    /* Letters d) e) */
    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p = rstp_get_port(r, port_no);
        p->designated_priority_vector.root_bridge_id = r->root_priority.root_bridge_id;
        p->designated_priority_vector.root_path_cost = r->root_priority.root_path_cost;
        p->designated_priority_vector.designated_bridge_id = r->bridge_identifier;
        p->designated_priority_vector.designated_port_id = p->port_id;
        p->designated_times = r->root_times;
        p->designated_times.hello_time = r->bridge_times.hello_time;
    }
    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p = rstp_get_port(r, port_no);
        switch (p->info_is) {
        case INFO_IS_DISABLED:
            p->selected_role = ROLE_DISABLED;
            break;
        case INFO_IS_AGED:
            p->updt_info = true;
            p->selected_role = ROLE_DESIGNATED;
            break;
        case INFO_IS_MINE:
            p->selected_role = ROLE_DESIGNATED;
            if ((rstp_priority_vector_is_superior(&p->port_priority, &p->designated_priority_vector) != SAME) ||
                (memcmp(&p->designated_times, &r->root_times, sizeof(struct rstp_times)) != 0)) {
                p->updt_info = true;
            }
            break;
        case INFO_IS_RECEIVED:
            if (vsel == p->port_number) { /* Letter i) */
                p->selected_role = ROLE_ROOT;
                p->updt_info = false;
            } else if (rstp_priority_vector_is_superior(&p->designated_priority_vector, &p->port_priority) == NOT_SUPERIOR) {
        if (p->port_priority.designated_bridge_id != r->bridge_identifier) {
                    p->selected_role = ROLE_ALTERNATE;
                    p->updt_info = false;
                } else {
                    p->selected_role = ROLE_BACKUP;
                    p->updt_info = false;
                }
            } else {
                p->selected_role = ROLE_DESIGNATED;
                p->updt_info = true;
            }
            break;
        default:
            OVS_NOT_REACHED();
            /* no break */
        }
    }
    seq_change(connectivity_seq_get());
}

void
set_selected_tree(struct rstp *r)
{
    int port_no;

    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p = rstp_get_port(r, port_no);
        if (p->reselect) {
            return;
        }
    }
     for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p = rstp_get_port(r, port_no);
        p->selected = true;
    }
}

int
port_role_selection_sm(struct rstp *r)
{
    enum port_role_selection_state_machine old_state;
    int port_no;
    struct rstp_port *p;
    
    old_state = r->port_role_selection_sm_state;
    
    switch (r->port_role_selection_sm_state) {
    case PORT_ROLE_SELECTION_SM_INIT:
        if (r->begin)
            r->port_role_selection_sm_state = PORT_ROLE_SELECTION_SM_INIT_BRIDGE_EXEC;
        break;
    case PORT_ROLE_SELECTION_SM_INIT_BRIDGE_EXEC:
        updt_role_disabled_tree(r);
        r->port_role_selection_sm_state = PORT_ROLE_SELECTION_SM_INIT_BRIDGE;
        /* no break */
    case PORT_ROLE_SELECTION_SM_INIT_BRIDGE:
        r->port_role_selection_sm_state = PORT_ROLE_SELECTION_SM_ROLE_SELECTION_EXEC;
        break;
    case PORT_ROLE_SELECTION_SM_ROLE_SELECTION_EXEC:
        clear_reselect_tree(r);
        updt_roles_tree(r);
        set_selected_tree(r);
        r->port_role_selection_sm_state = PORT_ROLE_SELECTION_SM_ROLE_SELECTION;
        /* no break */
    case PORT_ROLE_SELECTION_SM_ROLE_SELECTION:
        for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
            p = rstp_get_port(r, port_no);
            if (p->reselect) {
                r->port_role_selection_sm_state = PORT_ROLE_SELECTION_SM_ROLE_SELECTION_EXEC;
                break;
            }
        }
        break;
    default:
        OVS_NOT_REACHED();
        /* no break */
    }
    if (old_state != r->port_role_selection_sm_state) {
        r->changes = true;
        VLOG_DBG("Port_role_selection_sm %d -> %d", old_state, r->port_role_selection_sm_state);
    }
    return 0;
}

/* Port State Machines */

/* [17.23 - Port receive state machine] */

void
updt_bpdu_version(struct rstp_port *p)  /* [17.21.22] */
{
    switch (p->received_bpdu_buffer.bpdu_type) {
    case CONFIGURATION_BPDU:
    case TOPOLOGY_CHANGE_NOTIFICATION_BPDU:
        p->rcvd_rstp = false;
        p->rcvd_stp = true;
        break;
    case RAPID_SPANNING_TREE_BPDU:
        p->rcvd_rstp = true;
        p->rcvd_stp = false;
        break;
    default:
        OVS_NOT_REACHED();
        /* no break */
    }
}

int
port_receive_sm(struct rstp_port *p)
{
    enum port_receive_state_machine old_state;
    struct rstp *r;

    old_state = p->port_receive_sm_state;
    r = p->rstp;
    
    switch (p->port_receive_sm_state) {
    case PORT_RECEIVE_SM_INIT:
        if (r->begin || ((p->rcvd_bpdu || (p->edge_delay_while != r->migrate_time)) && !p->port_enabled)) {
            p->port_receive_sm_state = PORT_RECEIVE_SM_DISCARD_EXEC;
        }
        break;
    case PORT_RECEIVE_SM_DISCARD_EXEC:
        p->rcvd_bpdu = p->rcvd_rstp = p->rcvd_stp = false;
        p->rcvd_msg = false;
        p->edge_delay_while = r->migrate_time;
        p->port_receive_sm_state = PORT_RECEIVE_SM_DISCARD;
        /* no break */
    case PORT_RECEIVE_SM_DISCARD:
        if (p->rcvd_bpdu && p->port_enabled) {
            p->port_receive_sm_state = PORT_RECEIVE_SM_RECEIVE_EXEC;
        }
        break;
    case PORT_RECEIVE_SM_RECEIVE_EXEC:
        updt_bpdu_version(p);
        p->oper_edge = p->rcvd_bpdu = false;
        p->rcvd_msg = true;
        p->edge_delay_while = r->migrate_time;
        p->port_receive_sm_state = PORT_RECEIVE_SM_RECEIVE;
        /* no break */
    case PORT_RECEIVE_SM_RECEIVE:
        if (p->rcvd_bpdu && p->port_enabled && !p->rcvd_msg) {
            p->port_receive_sm_state = PORT_RECEIVE_SM_RECEIVE_EXEC;
        }
        break;
    default:
        OVS_NOT_REACHED();
        /* no break */
    }
    if (old_state != p->port_receive_sm_state) {
        r->changes = true;
        VLOG_DBG("%s, port %u: Port_receive_sm %d -> %d", p->rstp->name, p->port_number, old_state, p->port_receive_sm_state);
    }
    return 0;
}

/* [17.24 - Port Protocol Migration state machine] */
int
port_protocol_migration_sm(struct rstp_port *p)
{
    enum port_protocol_migration_state_machine old_state;
    struct rstp *r;
    
    old_state = p->port_protocol_migration_sm_state;
    r = p->rstp;

    switch (p->port_protocol_migration_sm_state) {
    case PORT_PROTOCOL_MIGRATION_SM_INIT:
    p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_CHECKING_RSTP_EXEC;
        /* no break */
    case PORT_PROTOCOL_MIGRATION_SM_CHECKING_RSTP_EXEC:
        p->mcheck = false;
        p->send_rstp = r->rstp_version;
        p->mdelay_while = r->migrate_time;
        p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_CHECKING_RSTP;
        /* no break */
    case PORT_PROTOCOL_MIGRATION_SM_CHECKING_RSTP:
        if (p->mdelay_while == 0) {
        p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_SENSING_EXEC;
        }
        if ((p->mdelay_while != r->migrate_time) && !p->port_enabled) {
            p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_CHECKING_RSTP_EXEC;
        }
        break;
    case PORT_PROTOCOL_MIGRATION_SM_SELECTING_STP_EXEC:
    p->send_rstp = false;
        p->mdelay_while = r->migrate_time;
        p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_SELECTING_STP;
        /* no break */
    case PORT_PROTOCOL_MIGRATION_SM_SELECTING_STP:
        if ((p->mdelay_while == 0) || (!p->port_enabled) || p->mcheck) {
            p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_SENSING_EXEC;
        }
        break;
    case PORT_PROTOCOL_MIGRATION_SM_SENSING_EXEC:
        p->rcvd_rstp = false;
        p->rcvd_stp = false;
        p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_SENSING;
        /* no break */
    case PORT_PROTOCOL_MIGRATION_SM_SENSING:
        if (!p->port_enabled || p->mcheck || ((r->rstp_version) && !p->send_rstp && p->rcvd_rstp)) {
            p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_CHECKING_RSTP_EXEC;
        }
        if (p->send_rstp && p->rcvd_stp) {
            p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_SELECTING_STP_EXEC;
        }
        break;
    default:
        OVS_NOT_REACHED();
        /* no break */
    }
    if (old_state != p->port_protocol_migration_sm_state) {
        r->changes = true;
        VLOG_DBG("%s, port %u: port_protocol_migration_sm %d -> %d", p->rstp->name, p->port_number, old_state, p->port_protocol_migration_sm_state);
    }

    return 0;
}

/* [17.25 - Bridge Detection state machine] */
int
bridge_detection_sm(struct rstp_port *p)
{
    enum bridge_detection_state_machine old_state;
    struct rstp *r;

    old_state = p->bridge_detection_sm_state;
    r = p->rstp;

    switch (p->bridge_detection_sm_state) {
    case BRIDGE_DETECTION_SM_INIT:
    if (r->begin && p->admin_edge) {
            p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_EDGE_EXEC;
        } else if (r->begin && !p->admin_edge) {
            p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_NOT_EDGE_EXEC;
        }
        break;
    case BRIDGE_DETECTION_SM_EDGE_EXEC:
        p->oper_edge = true;
        p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_EDGE;
        /* no break */
    case BRIDGE_DETECTION_SM_EDGE:
        if ((!p->port_enabled && !p->admin_edge) || !p->oper_edge) {
            p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_NOT_EDGE_EXEC;
        }
        break;
    case BRIDGE_DETECTION_SM_NOT_EDGE_EXEC:
        p->oper_edge = false;
        p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_NOT_EDGE;
        /* no break */
    case BRIDGE_DETECTION_SM_NOT_EDGE:
        if ((!p->port_enabled && p->admin_edge) || ((p->edge_delay_while == 0) && p->auto_edge && p->send_rstp && p->proposing)) {
            p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_EDGE_EXEC;
        }
        break;
    default:
        OVS_NOT_REACHED();
        /* no break */
    }
    if (old_state != p->bridge_detection_sm_state) {
        r->changes = true;
        VLOG_DBG("%s, port %u: bridge_detection_sm %d -> %d", p->rstp->name, p->port_number, old_state, p->bridge_detection_sm_state);
    }
    return 0;
}

/* [17.26 - Port Transmit state machine] */
static void
rstp_send_bpdu(struct rstp_port *p, const void *bpdu, size_t bpdu_size)
OVS_REQUIRES(mutex)
{
    struct eth_header *eth;
    struct llc_header *llc;
    struct ofpbuf *pkt;

    /* Skeleton. */
    pkt = ofpbuf_new(ETH_HEADER_LEN + LLC_HEADER_LEN + bpdu_size);
    eth = ofpbuf_put_zeros(pkt, sizeof *eth);
    llc = ofpbuf_put_zeros(pkt, sizeof *llc);
    ofpbuf_set_frame(pkt, eth);
    ofpbuf_set_l3(pkt, ofpbuf_put(pkt, bpdu, bpdu_size));

    /* 802.2 header. */
    memcpy(eth->eth_dst, eth_addr_stp, ETH_ADDR_LEN);
    /* p->rstp->send_bpdu() must fill in source address. */
    eth->eth_type = htons(ofpbuf_size(pkt) - ETH_HEADER_LEN);

    /* LLC header. */
    llc->llc_dsap = STP_LLC_DSAP;
    llc->llc_ssap = STP_LLC_SSAP;
    llc->llc_cntl = STP_LLC_CNTL;
    p->rstp->send_bpdu(pkt, rstp_port_index(p), p->rstp->aux);
}

void
record_agreement(struct rstp_port *p)
{
    struct rstp *r;
    
    r = p->rstp;
    if (r->rstp_version && p->oper_point_to_point_mac && ((p->received_bpdu_buffer.flags & BPDU_FLAG_AGREEMENT))) {
        p->agreed = true;
        p->proposing = false;
    } else {
        p->agreed = false;
    }
}

void
set_tc_flags(struct rstp_port *p)
{
    /* Sets rcvd_tc and/or rcvd_tc_ack if the Topology Change and/or Topology
       Change Acknowledgment flags, respectively, are set in a ConfigBPDU or
       RST BPDU. */
    if (p->received_bpdu_buffer.bpdu_type == CONFIGURATION_BPDU ||
            p->received_bpdu_buffer.bpdu_type == RAPID_SPANNING_TREE_BPDU) {
        if ((p->received_bpdu_buffer.flags & BPDU_FLAG_TOPCHANGE) != 0) {
            p->rcvd_tc = true;
        }
        if ((p->received_bpdu_buffer.flags & BPDU_FLAG_TOPCHANGEACK) != 0) {
            p->rcvd_tc_ack = true;
        }
    }
    /* Sets rcvd_tcn true if the BPDU is a TCN BPDU. */
    if (p->received_bpdu_buffer.bpdu_type == TOPOLOGY_CHANGE_NOTIFICATION_BPDU) {
        p->rcvd_tcn = true;
    }
}

void
record_dispute(struct rstp_port *p)
{
    if ((p->received_bpdu_buffer.flags & BPDU_FLAG_LEARNING) != 0) {
        p->agreed = true;
        p->proposing = false;
    }
}

void
record_proposal(struct rstp_port *p)
{
    unsigned int role = ((p->received_bpdu_buffer.flags) & 0xC) >> 2;
    if ((role == PORT_DES) && ((p->received_bpdu_buffer.flags & BPDU_FLAG_PROPOSAL) != 0)) {
        p->proposed = true;
    }
}

void
record_priority(struct rstp_port *p)
{
    p->port_priority.root_bridge_id = p->msg_priority.root_bridge_id;
    p->port_priority.root_path_cost = p->msg_priority.root_path_cost;
    p->port_priority.designated_bridge_id = p->msg_priority.designated_bridge_id;
    p->port_priority.designated_port_id = p->msg_priority.designated_port_id;
}

void
record_times(struct rstp_port *p)
{
    p->port_times.message_age = p->msg_times.message_age;
    p->port_times.max_age = p->msg_times.max_age;
    p->port_times.forward_delay = p->msg_times.forward_delay;
    if (p->msg_times.hello_time > 1) {
        p->port_times.hello_time = p->msg_times.hello_time;
    } else {
        p->port_times.hello_time = 1;
    }
}

void
updt_rcvd_info_while(struct rstp_port *p)
{
    if (p->port_times.message_age + 1 <= p->port_times.max_age) {
        p->rcvd_info_while = p->port_times.hello_time * 3;
     } else {
        p->rcvd_info_while = 0;
     }
}

ovs_be16
time_encode(uint8_t value)
{
    return htons(value * 256);
}

uint8_t
time_decode(ovs_be16 encoded)
{
    return (ntohs(encoded) / 256);
}

/* [17.21.19] */
void
tx_config(struct rstp_port *p)
{
    struct rstp_bpdu bpdu;
    
    memset(&bpdu, 0, sizeof(struct rstp_bpdu));

    bpdu.protocol_identifier = htons(0);
    bpdu.protocol_version_identifier = 0;
    bpdu.bpdu_type = CONFIGURATION_BPDU;
    bpdu.root_bridge_id = htonll(p->designated_priority_vector.root_bridge_id);
    bpdu.root_path_cost = htonl(p->designated_priority_vector.root_path_cost);
    bpdu.designated_bridge_id = htonll(p->designated_priority_vector.designated_bridge_id);
    bpdu.designated_port_id = htons(p->designated_priority_vector.designated_port_id);   
    bpdu.message_age = time_encode(p->designated_times.message_age);
    bpdu.max_age = time_encode(p->designated_times.max_age);
    bpdu.hello_time = time_encode(p->designated_times.hello_time);
    bpdu.forward_delay = time_encode(p->designated_times.forward_delay);
    if (p->tc_while !=0) {
        bpdu.flags |= BPDU_FLAG_TOPCHANGE;
    }
    if (p->tc_ack !=0) {
        bpdu.flags |= BPDU_FLAG_TOPCHANGEACK;
    }
    rstp_send_bpdu(p, &bpdu, sizeof(struct rstp_bpdu));
}

/* [17.21.20] */
void
tx_rstp(struct rstp_port *p)
{
    struct rstp_bpdu bpdu;

    memset(&bpdu, 0, sizeof(struct rstp_bpdu));    

    bpdu.protocol_identifier = htons(0);
    bpdu.protocol_version_identifier = 2;
    bpdu.bpdu_type = RAPID_SPANNING_TREE_BPDU;
    bpdu.root_bridge_id = htonll(p->designated_priority_vector.root_bridge_id);
    bpdu.root_path_cost = htonl(p->designated_priority_vector.root_path_cost);
    bpdu.designated_bridge_id = htonll(p->designated_priority_vector.designated_bridge_id);
    bpdu.designated_port_id = htons(p->designated_priority_vector.designated_port_id);
    bpdu.message_age = time_encode(p->designated_times.message_age);
    bpdu.max_age = time_encode(p->designated_times.max_age);
    bpdu.hello_time = time_encode(p->designated_times.hello_time);
    bpdu.forward_delay = time_encode(p->designated_times.forward_delay);
    switch (p->role) {
    case ROLE_ROOT:
        bpdu.flags = PORT_ROOT<<2;
        break;
    case ROLE_DESIGNATED:
        bpdu.flags = PORT_DES<<2;
        break;
    case ROLE_ALTERNATE:
    case ROLE_BACKUP:
        bpdu.flags = PORT_ALT_BACK<<2;
        break;
    case ROLE_DISABLED:
        /* should not happen! */
        OVS_NOT_REACHED();
        break;
    }
    if (p->agree) {
        bpdu.flags |= BPDU_FLAG_AGREEMENT;
    }
    if (p->proposing) {
        bpdu.flags |= BPDU_FLAG_PROPOSAL;
    }
    if (p->tc_while !=0) {
        bpdu.flags |= BPDU_FLAG_TOPCHANGE;
    }
    if (p->learning) {
        bpdu.flags |= BPDU_FLAG_LEARNING;
    }
    if (p->forwarding) {
        bpdu.flags |= BPDU_FLAG_FORWARDING;
    }
    rstp_send_bpdu(p, &bpdu, sizeof(struct rstp_bpdu));
}

/* [17.21.21] */
void
tx_tcn(struct rstp_port *p)
{
    struct rstp_bpdu bpdu;
    
    memset(&bpdu, 0, sizeof(struct rstp_bpdu));

    bpdu.protocol_identifier = htons(0);
    bpdu.protocol_version_identifier = 0;
    bpdu.bpdu_type = TOPOLOGY_CHANGE_NOTIFICATION_BPDU;
    rstp_send_bpdu(p, &bpdu, sizeof(struct rstp_bpdu));
}

int
port_transmit_sm(struct rstp_port *p)
{
    enum port_transmit_state_machine old_state;
    struct rstp *r;
    
    old_state = p->port_transmit_sm_state;
    r = p->rstp;

    switch (p->port_transmit_sm_state) {
    case PORT_TRANSMIT_SM_INIT:
        if (r->begin) {
            p->port_transmit_sm_state = PORT_TRANSMIT_SM_TRANSMIT_INIT_EXEC;
        }
        break;
    case PORT_TRANSMIT_SM_TRANSMIT_INIT_EXEC:
        p->new_info = true;
        p->tx_count = 0;
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_TRANSMIT_INIT;
        /* no break */
    case PORT_TRANSMIT_SM_TRANSMIT_INIT:
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_IDLE_EXEC;
        break;
    case PORT_TRANSMIT_SM_TRANSMIT_PERIODIC_EXEC:
        p->new_info = p->new_info || (p->role==ROLE_DESIGNATED || (p->role==ROLE_ROOT && p->tc_while!=0));
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_TRANSMIT_PERIODIC;
        /* no break */
    case PORT_TRANSMIT_SM_TRANSMIT_PERIODIC:
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_IDLE_EXEC;
        break;
    case PORT_TRANSMIT_SM_IDLE_EXEC:
        p->hello_when = r->bridge_hello_time;
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_IDLE;
        /* no break */
    case PORT_TRANSMIT_SM_IDLE:
        if (p->role == ROLE_DISABLED) {
            break;
        }
        if (p->send_rstp && p->new_info && (p->tx_count < r->transmit_hold_count) && (p->hello_when != 0) && p->selected && !p->updt_info) {
            p->port_transmit_sm_state = PORT_TRANSMIT_SM_TRANSMIT_RSTP_EXEC;
        }
        if (p->hello_when == 0 && p->selected && !p->updt_info) {
            p->port_transmit_sm_state = PORT_TRANSMIT_SM_TRANSMIT_PERIODIC_EXEC;
        }
        if (!p->send_rstp && p->new_info && (p->role == ROLE_ROOT) && (p->tx_count < r->transmit_hold_count) && (p->hello_when != 0) && p->selected && !p->updt_info) {
            p->port_transmit_sm_state = PORT_TRANSMIT_SM_TRANSMIT_TCN_EXEC;
        }
        if (!p->send_rstp && p->new_info && (p->role == ROLE_DESIGNATED) && (p->tx_count < r->transmit_hold_count) && (p->hello_when != 0) && p->selected && !p->updt_info) {
            p->port_transmit_sm_state = PORT_TRANSMIT_SM_TRANSMIT_CONFIG_EXEC;
        }
        break;
    case PORT_TRANSMIT_SM_TRANSMIT_CONFIG_EXEC:
        p->new_info = false;
        tx_config(p);
        p->tx_count += 1;
        p->tc_ack = false;
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_TRANSMIT_CONFIG;
        /* no break */
    case PORT_TRANSMIT_SM_TRANSMIT_CONFIG:
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_IDLE_EXEC;
        break;
    case PORT_TRANSMIT_SM_TRANSMIT_TCN_EXEC:
        p->new_info = false;
        tx_tcn(p);
        p->tx_count += 1;
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_TRANSMIT_TCN;
        /* no break */
    case PORT_TRANSMIT_SM_TRANSMIT_TCN:
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_IDLE_EXEC;
        break;
    case PORT_TRANSMIT_SM_TRANSMIT_RSTP_EXEC:
        p->new_info = false;
        tx_rstp(p);
        p->tx_count += 1;
        p->tc_ack = false;
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_TRANSMIT_RSTP;
        /* no break */
    case PORT_TRANSMIT_SM_TRANSMIT_RSTP:
        p->port_transmit_sm_state = PORT_TRANSMIT_SM_IDLE_EXEC;
        break;
    default:
        OVS_NOT_REACHED();
        /* no break */
    }
    if (old_state != p->port_transmit_sm_state) {
        r->changes = true;
        VLOG_DBG("%s, port %u: port_transmit_sm %d -> %d", p->rstp->name, p->port_number, old_state, p->port_transmit_sm_state);
    }
    return 0;
}

/* [17.27 Port Information state machine] */
#define RECEIVED 0
#define MINE 1

int
rcv_info(struct rstp_port *p)
{
    enum vector_comparison cp;
    int ct;
    unsigned int role;

    p->msg_priority.root_bridge_id = ntohll(p->received_bpdu_buffer.root_bridge_id);
    p->msg_priority.root_path_cost = ntohl(p->received_bpdu_buffer.root_path_cost);
    p->msg_priority.designated_bridge_id = ntohll(p->received_bpdu_buffer.designated_bridge_id);
    p->msg_priority.designated_port_id = ntohs(p->received_bpdu_buffer.designated_port_id);

    p->msg_times.forward_delay = time_decode(p->received_bpdu_buffer.forward_delay);
    p->msg_times.hello_time = time_decode(p->received_bpdu_buffer.hello_time);
    p->msg_times.max_age = time_decode(p->received_bpdu_buffer.max_age);
    p->msg_times.message_age = time_decode(p->received_bpdu_buffer.message_age);

    cp = rstp_priority_vector_is_superior(&p->msg_priority, &p->port_priority);
    ct = memcmp(&p->port_times, &p->msg_times, sizeof(struct rstp_times));
    role = ((p->received_bpdu_buffer.flags) & 0xC) >> 2;

    /*Returns SuperiorDesignatedInfo if:
      a) The received message conveys a Designated Port Role, and
        1) The message priority is superior (17.6) to the Port.s port priority
           vector, or
        2) The message priority vector is the same as the Port.s port priority
           vector, and any of the received timer parameter values (msg_times.
           17.19.15) differ from those already held for the Port (port_times
           17.19.22).
      NOTE: Configuration BPDU explicitly conveys a Designated Port Role.*/
    if ((role == PORT_DES || p->received_bpdu_buffer.bpdu_type == CONFIGURATION_BPDU) && ((cp == SUPERIOR_ABSOLUTE) || (cp == SUPERIOR_SAME_DES) || ((cp == SAME) && ct != 0))) {
        return SUPERIOR_DESIGNATED_INFO;
    }

    /*Returns RepeatedDesignatedInfo if:
      b) The received message conveys Designated Port Role, and a message
         priority vector and timer parameters that are the same as the Port's
         port priority vector or timer values.*/
    else if ((role == PORT_DES) && (cp == SAME) && (ct == 0)) {
        return REPEATED_DESIGNATED_INFO;
    }

    /*Returns InferiorDesignatedInfo if:
      c) The received message conveys a Designated Port Role, and a message
         priority vector that is worse than the Port.s port priority vector.*/
    else if ((role == PORT_DES) && (cp == NOT_SUPERIOR)) {
        return INFERIOR_DESIGNATED_INFO;
    }

    /*Returns InferiorRootAlternateInfo if:
      d) The received message conveys a Root Port, Alternate Port, or Backup
      Port Role and a message priority that is the same as or worse than the
      port priority vector.*/
    else if ((role == PORT_ROOT || role == PORT_ALT_BACK) && (cp == NOT_SUPERIOR || cp == SAME)) {
        return INFERIOR_ROOT_ALTERNATE_INFO;
    }

    /* Otherwise, returns OtherInfo. */
    else {
        return OTHER_INFO;
    }
}

int
better_or_same_info(struct rstp_port *p, int new_info_is)
{
    /* >= SUPERIOR_ABSOLUTE means that the vector is better or the same. */
    return ((new_info_is == RECEIVED && p->info_is == INFO_IS_RECEIVED && rstp_priority_vector_is_superior(&p->msg_priority, &p->port_priority) >= SUPERIOR_ABSOLUTE)
            || (new_info_is == MINE && p->info_is == INFO_IS_MINE && rstp_priority_vector_is_superior(&p->designated_priority_vector, &p->port_priority) >= SUPERIOR_ABSOLUTE));
}

int
port_information_sm(struct rstp_port *p)
{
    enum port_information_state_machine old_state;
    struct rstp *r;

    old_state = p->port_information_sm_state;
    r = p->rstp;

    if (!p->port_enabled && (p->info_is != INFO_IS_DISABLED)) {
        p->port_information_sm_state = PORT_INFORMATION_SM_DISABLED_EXEC;
    }
    switch (p->port_information_sm_state) {
    case PORT_INFORMATION_SM_INIT:
        if (r->begin) {
            p->port_information_sm_state = PORT_INFORMATION_SM_DISABLED_EXEC;
        }
        break;
    case PORT_INFORMATION_SM_DISABLED_EXEC:
        p->rcvd_msg = false;
        p->proposing = p->proposed = p->agree = p->agreed = false;
        p->rcvd_info_while = 0;
        p->info_is = INFO_IS_DISABLED;
        p->reselect = true;
        p->selected = false;
        p->port_information_sm_state = PORT_INFORMATION_SM_DISABLED;
        /* no break */
    case PORT_INFORMATION_SM_DISABLED:
        if (p->port_enabled) {
            p->port_information_sm_state = PORT_INFORMATION_SM_AGED_EXEC;
        }
        if (p->rcvd_msg) {
        p->port_information_sm_state = PORT_INFORMATION_SM_DISABLED_EXEC;
        }
        break;
    case PORT_INFORMATION_SM_AGED_EXEC:
        p->info_is = INFO_IS_AGED;
        p->reselect = true;
        p->selected = false;
        p->port_information_sm_state = PORT_INFORMATION_SM_AGED;
        /* no break */
    case PORT_INFORMATION_SM_AGED:
        if (p->selected && p->updt_info) {
            p->port_information_sm_state = PORT_INFORMATION_SM_UPDATE_EXEC;
        }
        break;
    case PORT_INFORMATION_SM_UPDATE_EXEC:
        p->proposing = p->proposed = false;
        p->agreed = p->agreed && better_or_same_info(p, MINE); /* MINE is not specified in Standard 802.1D-2004. */
        p->synced = p->synced && p->agreed;
        p->port_priority.root_bridge_id = p->designated_priority_vector.root_bridge_id;
        p->port_priority.root_path_cost = p->designated_priority_vector.root_path_cost;
        p->port_priority.designated_bridge_id = p->designated_priority_vector.designated_bridge_id;
        p->port_priority.designated_port_id = p->designated_priority_vector.designated_port_id;
        p->port_times = p->designated_times;
        p->updt_info = false;
        p->info_is = INFO_IS_MINE;
        p->new_info = true;
        p->port_information_sm_state = PORT_INFORMATION_SM_UPDATE;
        /* no break */
    case PORT_INFORMATION_SM_UPDATE:
        p->port_information_sm_state = PORT_INFORMATION_SM_CURRENT_EXEC;
        break;
    case PORT_INFORMATION_SM_CURRENT_EXEC:
        p->port_information_sm_state = PORT_INFORMATION_SM_CURRENT;
        /* no break */
    case PORT_INFORMATION_SM_CURRENT:
        if (p->rcvd_msg && !p->updt_info) {
            p->port_information_sm_state = PORT_INFORMATION_SM_RECEIVE_EXEC;
        } else if (p->selected && p->updt_info) {
            p->port_information_sm_state = PORT_INFORMATION_SM_UPDATE_EXEC;
        } else if ( (p->info_is == INFO_IS_RECEIVED) && (p->rcvd_info_while == 0) && !p->updt_info && !p->rcvd_msg) {
            p->port_information_sm_state = PORT_INFORMATION_SM_AGED_EXEC;
        }
        break;
    case PORT_INFORMATION_SM_RECEIVE_EXEC:
        p->rcvd_info = rcv_info(p);
        p->port_information_sm_state = PORT_INFORMATION_SM_RECEIVE;
        /* no break */
    case PORT_INFORMATION_SM_RECEIVE:
        switch (p->rcvd_info) {
        case SUPERIOR_DESIGNATED_INFO:
            p->port_information_sm_state = PORT_INFORMATION_SM_SUPERIOR_DESIGNATED_EXEC;
            break;
        case REPEATED_DESIGNATED_INFO:
            p->port_information_sm_state = PORT_INFORMATION_SM_REPEATED_DESIGNATED_EXEC;
            break;
        case INFERIOR_DESIGNATED_INFO:
            p->port_information_sm_state = PORT_INFORMATION_SM_INFERIOR_DESIGNATED_EXEC;
            break;
        case INFERIOR_ROOT_ALTERNATE_INFO:
            p->port_information_sm_state = PORT_INFORMATION_SM_NOT_DESIGNATED_EXEC;
            break;
        case OTHER_INFO:
            p->port_information_sm_state = PORT_INFORMATION_SM_OTHER_EXEC;
            break;
        default:
            OVS_NOT_REACHED();
            /* no break */
        }
        break;
    case PORT_INFORMATION_SM_OTHER_EXEC:
        p->rcvd_msg = false;
        p->port_information_sm_state = PORT_INFORMATION_SM_OTHER;
        /* no break */
    case PORT_INFORMATION_SM_OTHER:
        p->port_information_sm_state = PORT_INFORMATION_SM_CURRENT_EXEC;
        break;
    case PORT_INFORMATION_SM_NOT_DESIGNATED_EXEC:
        record_agreement(p);
        set_tc_flags(p);
        p->rcvd_msg = false;
        p->port_information_sm_state = PORT_INFORMATION_SM_NOT_DESIGNATED;
        /* no break */
    case PORT_INFORMATION_SM_NOT_DESIGNATED:
        p->port_information_sm_state = PORT_INFORMATION_SM_CURRENT_EXEC;
        break;
    case PORT_INFORMATION_SM_INFERIOR_DESIGNATED_EXEC:
        record_dispute(p);
        p->rcvd_msg = false;
        p->port_information_sm_state = PORT_INFORMATION_SM_INFERIOR_DESIGNATED;
        /* no break */
    case PORT_INFORMATION_SM_INFERIOR_DESIGNATED:
        p->port_information_sm_state = PORT_INFORMATION_SM_CURRENT_EXEC;
        break;
    case PORT_INFORMATION_SM_REPEATED_DESIGNATED_EXEC:
        record_proposal(p);
        set_tc_flags(p);
        updt_rcvd_info_while(p);
        p->rcvd_msg = false;
        p->port_information_sm_state = PORT_INFORMATION_SM_REPEATED_DESIGNATED;
        /* no break */
    case PORT_INFORMATION_SM_REPEATED_DESIGNATED:
        p->port_information_sm_state = PORT_INFORMATION_SM_CURRENT_EXEC;
        break;
    case PORT_INFORMATION_SM_SUPERIOR_DESIGNATED_EXEC:
        p->agreed = p->proposing = false;
        record_proposal(p);
        set_tc_flags(p);
        p->agree = p->agree && better_or_same_info(p, RECEIVED); /* RECEIVED is not specified in Standard 802.1D-2004. */
        record_priority(p);
        record_times(p);
        updt_rcvd_info_while(p);
        p->info_is = INFO_IS_RECEIVED;
        p->reselect = true;
        p->selected = false;
        p->rcvd_msg = false;
        p->port_information_sm_state = PORT_INFORMATION_SM_SUPERIOR_DESIGNATED;
        /* no break */
    case PORT_INFORMATION_SM_SUPERIOR_DESIGNATED:
        p->port_information_sm_state = PORT_INFORMATION_SM_CURRENT_EXEC;
        break;
    default:
        OVS_NOT_REACHED();
        /* no break */
    }
    if (old_state != p->port_information_sm_state) {
        r->changes = true;
        VLOG_DBG("Port_information_sm %d -> %d", old_state, p->port_information_sm_state);
    }
    return 0;
}

/* [17.29 Port Role Transitions state machine] */

void
set_re_root_tree(struct rstp_port *p)
{
    struct rstp *r;
    int port_no;

    r = p->rstp;
    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
    struct rstp_port *p1 = rstp_get_port(r, port_no);
        p1->re_root = true;
    }
}

void
set_sync_tree(struct rstp_port *p)
{
    struct rstp *r;
    int port_no;

    r = p->rstp;
    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p1 = rstp_get_port(r, port_no);
        p1->sync = true;
    }
}

int
hello_time(struct rstp_port *p)
{
    return p->designated_times.hello_time;
}

int
fwd_delay(struct rstp_port *p)
{
    return p->designated_times.forward_delay;
}


int
forward_delay(struct rstp_port *p)
{
    if (p->send_rstp) {
        return hello_time(p);
    } else {
        return fwd_delay(p);
    }
}

int
edge_delay(struct rstp_port *p)
{
    struct rstp *r;
    
    r = p->rstp;
    if (p->oper_point_to_point_mac == 1) {
        return r->migrate_time;
    } else {
        return p->designated_times.max_age;
    }
}

int
check_selected_role_change(struct rstp_port *p, int current_role_state)
{
    if (p->selected && !p->updt_info && (p->role != p->selected_role) && (p->selected_role != current_role_state)) {
        VLOG_DBG("%s, port %u: Entering case. current: %s role: %s selected: %d",
                p->rstp->name, p->port_number, rstp_port_role_name(current_role_state),
                rstp_port_role_name(p->role), p->selected_role);
        switch (p->selected_role) {
        case ROLE_ROOT:
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_PORT_EXEC;
            return true;
        case ROLE_DESIGNATED:
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT_EXEC;
            return true;
        case ROLE_ALTERNATE:
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_BLOCK_PORT_EXEC;
            return true;
        case ROLE_BACKUP:
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_BLOCK_PORT_EXEC;
            return true;
        case ROLE_DISABLED:
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DISABLE_PORT_EXEC;
            return true;
        }
    }
    return false;
}

int
re_rooted(struct rstp_port *p)
{
    struct rstp *r;
    int port_no;
    
    r = p->rstp;
    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p1 = rstp_get_port(r, port_no);
        if ((p1 != p) && (p1->rr_while != 0)) {
            return false;
        }
    }
    return true;
}

int
all_synced(struct rstp *r)
{
    int port_no;

    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p = rstp_get_port(r, port_no);
        if (!(p->selected && p->role == p->selected_role && (p->role == ROLE_ROOT || p->synced == true))) {
            return false;
        }
    }
    return true;
}

int
port_role_transition_sm(struct rstp_port *p)
{
    enum port_role_transition_state_machine old_state;
    struct rstp *r;
    enum rstp_port_role last_role;

    old_state = p->port_role_transition_sm_state;
    r = p->rstp;
    last_role = p->role;

    switch (p->port_role_transition_sm_state) {
    case PORT_ROLE_TRANSITION_SM_INIT:
        if (r->begin) {
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_INIT_PORT_EXEC;
        }
        break;
    case PORT_ROLE_TRANSITION_SM_INIT_PORT_EXEC:
        p->role = ROLE_DISABLED;
        p->learn = p->forward = false;
        p->synced = false;
        p->sync = p->re_root = true;
        p->rr_while = p->designated_times.forward_delay;
        p->fd_while = p->designated_times.max_age;
        p->rb_while = 0;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DISABLE_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_DISABLE_PORT_EXEC:
        p->role = p->selected_role;
        p->learn = p->forward = false;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DISABLE_PORT;
        /* no break */
    case PORT_ROLE_TRANSITION_SM_DISABLE_PORT:
        if (check_selected_role_change(p, ROLE_DISABLED)) {
            break;
        }
        if (p->selected && !p->updt_info && !p->learning && !p->forwarding) {
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DISABLED_PORT_EXEC;
        }
        break;
    case PORT_ROLE_TRANSITION_SM_DISABLED_PORT_EXEC:
        p->fd_while = p->designated_times.max_age;
        p->synced = true;
        p->rr_while = 0;
        p->sync = p->re_root = false;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DISABLED_PORT;
        /* no break */
    case PORT_ROLE_TRANSITION_SM_DISABLED_PORT:
        if (check_selected_role_change(p, ROLE_DISABLED)) {
            break;
        }
        if (p->selected && !p->updt_info &&
            ((p->fd_while != p->designated_times.max_age) || p->sync || p->re_root || !p->synced)) {
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DISABLED_PORT_EXEC;
        }
        break;
    case PORT_ROLE_TRANSITION_SM_ROOT_PORT_EXEC:
        p->role = ROLE_ROOT;
        p->rr_while = p->designated_times.forward_delay;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_PORT;
        /* no break */
    case PORT_ROLE_TRANSITION_SM_ROOT_PORT:
        if (check_selected_role_change(p, ROLE_ROOT)) {
        break;
        }
        if (p->selected && !p->updt_info) {
            if (p->rr_while != p->designated_times.forward_delay) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_PORT_EXEC;
                break;
            }
            if (p->re_root && p->forward) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_REROOTED_EXEC;
                break;
            }
            if (((p->fd_while == 0) || ((re_rooted(p) && (p->rb_while == 0)) && (r->rstp_version))) && !p->learn) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_LEARN_EXEC;
                break;
            }
            if (((p->fd_while==0) || ((re_rooted(p) && (p->rb_while == 0)) && (r->rstp_version))) && p->learn && !p->forward) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_FORWARD_EXEC;
                break;
            }
            if (p->proposed && !p->agree) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_PROPOSED_EXEC;
                break;
            }
            if ((all_synced(r) && !p->agree) || (p->proposed && p->agree)) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_AGREED_EXEC;
                break;
            }
            if (!p->forward && !p->re_root) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_REROOT_EXEC;
                break;
            }
        }
    break;
    case PORT_ROLE_TRANSITION_SM_REROOT_EXEC:
        set_re_root_tree(p);
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_ROOT_AGREED_EXEC:
        p->proposed = p->sync = false;
        p->agree = p->new_info = true;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_ROOT_PROPOSED_EXEC:
        set_sync_tree(p);
        p->proposed = false;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_ROOT_FORWARD_EXEC:
        p->fd_while = 0;
        p->forward = true;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_ROOT_LEARN_EXEC:
        p->fd_while = forward_delay(p);
        p->learn = true;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_REROOTED_EXEC:
        p->re_root = false;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ROOT_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT_EXEC:
        p->role = ROLE_DESIGNATED;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT;
        /* no break */
    case PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT:
        if (check_selected_role_change(p, ROLE_DESIGNATED)) {
            break;
        }
        if (p->selected && !p->updt_info) {
            if (((p->sync && !p->synced) || (p->re_root && (p->rr_while !=0)) || p->disputed) &&
                !p->oper_edge && (p->learn || p->forward)) {
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_DISCARD_EXEC;
            }
            if (((p->fd_while==0)|| p->agreed || p->oper_edge) && ((p->rr_while==0) || !p->re_root) &&
            !p->sync && !p->learn) {
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_LEARN_EXEC;
            }
            if (((p->fd_while == 0) || p->agreed || p->oper_edge) && ((p->rr_while == 0) || !p->re_root) &&
                !p->sync && (p->learn && !p->forward)) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_FORWARD_EXEC;
            }
            if (!p->forward && !p->agreed && !p->proposing && !p->oper_edge) {
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_PROPOSE_EXEC;
            }
            if ((!p->learning && !p->forwarding && !p->synced) || (p->agreed && !p->synced) ||
            (p->oper_edge && !p->synced) || (p->sync && p->synced)) {
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_SYNCED_EXEC;
            }
            if ((p->rr_while == 0) && p->re_root) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_RETIRED_EXEC;
            }
        }
        break;
    case PORT_ROLE_TRANSITION_SM_DESIGNATED_RETIRED_EXEC:
        p->re_root = false;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_DESIGNATED_SYNCED_EXEC:
        p->rr_while = 0;
        p->synced = true;
        p->sync = false;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_DESIGNATED_PROPOSE_EXEC:
        p->proposing = true;
        p->edge_delay_while = edge_delay(p);
        p->new_info = true;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_DESIGNATED_FORWARD_EXEC:
        p->forward = true;
        p->fd_while = 0;
        p->agreed = p->send_rstp;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_DESIGNATED_LEARN_EXEC:
        p->learn = true;
        p->fd_while = forward_delay(p);
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_DESIGNATED_DISCARD_EXEC:
        p->learn = p->forward = p->disputed = false;
        p->fd_while = forward_delay(p);
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_DESIGNATED_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_ALTERNATE_PORT_EXEC:
        p->fd_while = p->designated_times.forward_delay;
        p->synced = true;
        p->rr_while = 0;
        p->sync = p->re_root = false;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ALTERNATE_PORT;
        /* no break */
    case PORT_ROLE_TRANSITION_SM_ALTERNATE_PORT:
        if (check_selected_role_change(p, ROLE_ALTERNATE)) {
            break;
        }
        if (p->selected && !p->updt_info) {
            if ((p->rb_while != (2 * p->designated_times.hello_time)) && (p->role == ROLE_BACKUP)) {
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_BACKUP_PORT_EXEC;
            }
            if ((p->fd_while != forward_delay(p)) || p->sync || p->re_root || !p->synced) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ALTERNATE_PORT_EXEC;
            }
            if (p->proposed && !p->agree) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ALTERNATE_PROPOSED_EXEC;
            }
            if (( all_synced(r) && !p->agree) || (p->proposed && p->agree)) {
                p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ALTERNATE_AGREED;
            }
        }
        break;
    case PORT_ROLE_TRANSITION_SM_ALTERNATE_AGREED:
        p->proposed = false;
        p->agree = true;
        p->new_info = true;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ALTERNATE_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_ALTERNATE_PROPOSED_EXEC:
        set_sync_tree(p);
        p->proposed = false;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ALTERNATE_PORT_EXEC;
        break;
    case PORT_ROLE_TRANSITION_SM_BLOCK_PORT_EXEC:
        p->role = p->selected_role;
        p->learn = p->forward = false;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_BLOCK_PORT;
        /* no break */
    case PORT_ROLE_TRANSITION_SM_BLOCK_PORT:
        if (check_selected_role_change(p, ROLE_ALTERNATE)) {
            break;
        }
        if (p->selected && !p->updt_info && !p->learning && !p->forwarding) {
            p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ALTERNATE_PORT_EXEC;
        }
        break;
    case PORT_ROLE_TRANSITION_SM_BACKUP_PORT_EXEC:
        p->rb_while = 2 * p->designated_times.hello_time;
        p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_ALTERNATE_PORT_EXEC;
        break;
    default:
        OVS_NOT_REACHED();
        /* no break */
    }
    if (old_state != p->port_role_transition_sm_state) {
        r->changes = true;
        VLOG_DBG("%s, port %u: Port_role_transition_sm %d -> %d", p->rstp->name, p->port_number, old_state, p->port_role_transition_sm_state);
    }
    if (last_role != p->role) {
        last_role = p->role;
        VLOG_DBG("%s, port %u, port role ["RSTP_PORT_ID_FMT"] = %s", p->rstp->name, p->port_number, p->port_id, rstp_port_role_name(p->role));
    }
    return 0;
}

/* [17.30 - Port state transition state machine] */

void
enable_learning(struct rstp_port *p)
{
    /* [17.21.6 enableLearning()] An implementation dependent procedure that
       causes the Learning Process (7.8) to start learning from frames received
       on the Port. The procedure does not complete until learning has been
       enabled. */
    rstp_port_set_state(p, RSTP_LEARNING);
    /* setLearning(p->index); done in update_rstp_port_state() in ofproto-dpif.c */
}

void
enable_forwarding(struct rstp_port *p)
{
    /* [17.21.5 enableForwarding()] An implementation dependent procedure that
       causes the Forwarding Process (7.7) to start forwarding frames through the
       Port. The procedure does not complete until forwarding has been enabled. */
    rstp_port_set_state(p, RSTP_FORWARDING);
    /* setForwarding(p->index); done in update_rstp_port_state() in ofproto-dpif.c */
}

void
disable_learning(struct rstp_port *p)
{
    /* [17.21.4 - disableLearning()] An implementation dependent procedure that
       causes the Learning Process (7.8) to stop learning from the source address
       of frames received on the Port. The procedure does not complete until
       learning has stopped. */
    rstp_port_set_state(p, RSTP_DISCARDING);
    /* setDiscarding(p->index); done in update_rstp_port_state() in ofproto-dpif.c */
}

void
disable_forwarding(struct rstp_port *p)
{
    /* [17.21.3 - disableForwarding()] An implementation dependent procedure
       that causes the Forwarding Process (7.7) to stop forwarding frames through
       the Port. The procedure does not complete until forwarding has stopped. */
    rstp_port_set_state(p, RSTP_DISCARDING);
    /* setDiscarding(p->index); done in update_rstp_port_state() in ofproto-dpif.c */
}

int
port_state_transition_sm(struct rstp_port *p)
{
    enum port_state_transition_state_machine old_state;
    struct rstp *r;

    old_state = p->port_state_transition_sm_state;
    r = p->rstp;

    switch (p->port_state_transition_sm_state) {
    case PORT_STATE_TRANSITION_SM_INIT:
        if (r->begin) {
            p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_DISCARDING_EXEC;
        }
        break;
    case PORT_STATE_TRANSITION_SM_DISCARDING_EXEC:
        disable_learning(p);
        p->learning = false;
        disable_forwarding(p);
        p->forwarding = false;
        p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_DISCARDING;
        /* no break */
    case PORT_STATE_TRANSITION_SM_DISCARDING:
        if (p->learn) {
            p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_LEARNING_EXEC;
        }
        break;
    case PORT_STATE_TRANSITION_SM_LEARNING_EXEC:
        enable_learning(p);
        p->learning = true;
        p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_LEARNING;
        /* no break */
    case PORT_STATE_TRANSITION_SM_LEARNING:
        if (!p->learn) {
            p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_DISCARDING_EXEC;
        }
        if (p->forward) {
            p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_FORWARDING_EXEC;
        }
        break;
    case PORT_STATE_TRANSITION_SM_FORWARDING_EXEC:
        enable_forwarding(p);
        p->forwarding = true;
        p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_FORWARDING;
        /* no break */
    case PORT_STATE_TRANSITION_SM_FORWARDING:
        if (!p->forward) {
            p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_DISCARDING_EXEC;
        }
        break;
    default:
        OVS_NOT_REACHED();
        /* no break */
    }
    if (old_state != p->port_state_transition_sm_state) {
        r->changes = true;
        VLOG_DBG("%s, port %u: Port_state_transition_sm %d -> %d", p->rstp->name, p->port_number, old_state, p->port_state_transition_sm_state);
    }
    return 0;
}

/* [17.31 - Topology Change state machine] */

void
new_tc_while(struct rstp_port *p)
{
    struct rstp *r;
    
    r = p->rstp;
    if (p->tc_while == 0 && p->send_rstp == true) {
        p->tc_while = r->bridge_hello_time + 1;
        p->new_info = true;
    }
    if (p->tc_while == 0 && p->send_rstp == false) {
        p->tc_while = r->bridge_max_age + r->bridge_forward_delay;
    }
}

/* [17.21.18 setTcPropTree()]
   Sets tcprop for all Ports except the Port that called the procedure.
*/
void
set_tc_prop_tree(struct rstp_port *p)
{
    struct rstp *r;
    int port_no;
    
    r = p->rstp;
    for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
        struct rstp_port *p1 = rstp_get_port(r, port_no);
        /* Set tc_prop on every port, except the one calling this function. */
        if (p1->port_number != p->port_number) {
            p1->tc_prop = true;
        }
    }
}

void
set_tc_prop_bridge(struct rstp_port *p)  /* not specified in 802.1D-2004. */
{
    set_tc_prop_tree(p); /* see 802.1w-2001. */
}

int
topology_change_sm(struct rstp_port *p)
{
    enum topology_change_state_machine old_state;
    struct rstp *r;

    old_state = p->topology_change_sm_state;
    r = p->rstp;

    switch (p->topology_change_sm_state) {
    case TOPOLOGY_CHANGE_SM_INIT:
        if (r->begin) {
            p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_INACTIVE_EXEC;
        }
        break;
    case TOPOLOGY_CHANGE_SM_INACTIVE_EXEC:
        p->fdb_flush = true;
        p->tc_while = 0;
        p->tc_ack = false;
        p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_INACTIVE;
        /* no break */
    case TOPOLOGY_CHANGE_SM_INACTIVE:
        if (p->learn && !p->fdb_flush) {
            p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_LEARNING_EXEC;
        }
        break;
    case TOPOLOGY_CHANGE_SM_LEARNING_EXEC:
        p->rcvd_tc = p->rcvd_tcn = p->rcvd_tc_ack = false;
        p->tc_prop = p->rcvd_tc_ack = false;
        p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_LEARNING;
        /* no break */
    case TOPOLOGY_CHANGE_SM_LEARNING:
        if ((p->role != ROLE_ROOT) && (p->role != ROLE_DESIGNATED) && !(p->learn || p->learning) && !(p->rcvd_tc || p->rcvd_tcn || p->rcvd_tc_ack || p->tc_prop)) {
            p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_INACTIVE_EXEC;
        }
        if (p->rcvd_tc || p->rcvd_tcn || p->rcvd_tc_ack || p->tc_prop) {
            p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_LEARNING_EXEC;
        }
        if (((p->role == ROLE_ROOT) || (p->role == ROLE_DESIGNATED)) && p->forward && !p->oper_edge) {
        p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_DETECTED_EXEC;
        }
        break;
    case TOPOLOGY_CHANGE_SM_DETECTED_EXEC:
        new_tc_while(p);
        set_tc_prop_tree(p);
        p->new_info = true;
        p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_ACTIVE_EXEC;
        /* no break */
    case TOPOLOGY_CHANGE_SM_ACTIVE_EXEC:
        p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_ACTIVE;
        /* no break */
    case TOPOLOGY_CHANGE_SM_ACTIVE:
        if (((p->role!=ROLE_ROOT) && (p->role!=ROLE_DESIGNATED)) || p->oper_edge) {
            p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_LEARNING_EXEC;
        }
        if (p->rcvd_tcn) {
            p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_NOTIFIED_TCN_EXEC;
        }
        if (p->rcvd_tc) {
            p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_NOTIFIED_TC_EXEC;
        }
        if (p->tc_prop && !p->oper_edge) {
            p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_PROPAGATING_EXEC;
        }
        if (p->rcvd_tc_ack) {
            p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_ACKNOWLEDGED_EXEC;
        }
        break;
    case TOPOLOGY_CHANGE_SM_ACKNOWLEDGED_EXEC:
        p->tc_while = 0;
        p->rcvd_tc_ack = false;
        p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_ACTIVE;
        break;
    case TOPOLOGY_CHANGE_SM_PROPAGATING_EXEC:
        new_tc_while(p);
        p->fdb_flush = true;
        p->tc_prop = false;
        p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_ACTIVE;
        break;
    case TOPOLOGY_CHANGE_SM_NOTIFIED_TC_EXEC:
        p->rcvd_tcn = p->rcvd_tc = false;
        if (p->role == ROLE_DESIGNATED) {
            p->tc_ack = true;
        }
        set_tc_prop_bridge(p);
        p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_ACTIVE;
        break;
    case TOPOLOGY_CHANGE_SM_NOTIFIED_TCN_EXEC:
        new_tc_while(p);
        p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_ACTIVE;
        break;
    default:
        OVS_NOT_REACHED();
        /* no break */
    }
    if (old_state != p->topology_change_sm_state) {
        r->changes = true;
        VLOG_DBG("Topology_change_sm %d -> %d", old_state, p->topology_change_sm_state);
    }
    return 0;
}

/****************************************************************************
 * [17.6] Priority vector calculation helper functions
 ****************************************************************************/

/*  [17.6]
    This message priority vector is superior to the port priority vector and
    will replace it if, and only if, the message priority vector is better than
    the port priority vector, or the message has been transmitted from the same
    Designated Bridge and Designated Port as the port priority vector, i.e.,
    if the following is true:
      ((RD  < RootBridgeID)) ||
      ((RD == RootBridgeID) && (RPCD < RootPathCost)) ||
      ((RD == RootBridgeID) && (RPCD == RootPathCost) && (D < designated_bridge_id)) ||
      ((RD == RootBridgeID) && (RPCD == RootPathCost) && (D == designated_bridge_id) && (PD < designated_port_id)) ||
      ((D  == designated_bridge_id.BridgeAddress) && (PD == designated_port_id.PortNumber))
*/
enum vector_comparison
rstp_priority_vector_is_superior(struct rstp_priority_vector *v1, struct rstp_priority_vector *v2)
{ 
    VLOG_DBG("v1: "RSTP_ID_FMT", %u, "RSTP_ID_FMT", %d", RSTP_ID_ARGS(v1->root_bridge_id), v1->root_path_cost, RSTP_ID_ARGS(v1->designated_bridge_id), v1->designated_port_id);
        VLOG_DBG("v2: "RSTP_ID_FMT", %u, "RSTP_ID_FMT", %d", RSTP_ID_ARGS(v2->root_bridge_id), v2->root_path_cost, RSTP_ID_ARGS(v2->designated_bridge_id), v2->designated_port_id);
/*
    if (memcmp(v1, v2, sizeof(struct rstp_priority_vector4)) < 0) {
        VLOG_DBG("superior_absolute");       
        return SUPERIOR_ABSOLUTE;
    }
    else if ((memcmp(v1, v2, sizeof(struct rstp_priority_vector4)) > 0) &&
            (v1->designated_bridge_id == v2->designated_bridge_id) &&
            (v1->designated_port_id == v2->designated_port_id)) {
        VLOG_DBG("superior_same_des");
        return SUPERIOR_SAME_DES;
    }
    else if (memcmp(v1, v2, sizeof(struct rstp_priority_vector)) == 0) {
        VLOG_DBG("same");
        return SAME;
    }
    else {
        VLOG_DBG("not_superior");
        return NOT_SUPERIOR;
    }
*/
    if ((v1->root_bridge_id < v2->root_bridge_id) ||
        ((v1->root_bridge_id == v2->root_bridge_id) && (v1->root_path_cost < v2->root_path_cost)) ||
        ((v1->root_bridge_id == v2->root_bridge_id) && (v1->root_path_cost == v2->root_path_cost) && (v1->designated_bridge_id < v2->designated_bridge_id)) ||
        ((v1->root_bridge_id == v2->root_bridge_id) && (v1->root_path_cost == v2->root_path_cost) && (v1->designated_bridge_id == v2->designated_bridge_id) && (v1->designated_port_id < v2->designated_port_id))) {
        VLOG_DBG("superior_absolute");
        return SUPERIOR_ABSOLUTE;
    }
    else if (((v1->root_bridge_id > v2->root_bridge_id) ||
                ((v1->root_bridge_id == v2->root_bridge_id) && (v1->root_path_cost > v2->root_path_cost)) ||
                ((v1->root_bridge_id == v2->root_bridge_id) && (v1->root_path_cost == v2->root_path_cost) && (v1->designated_bridge_id > v2->designated_bridge_id)) ||
                ((v1->root_bridge_id == v2->root_bridge_id) && (v1->root_path_cost == v2->root_path_cost) && (v1->designated_bridge_id == v2->designated_bridge_id) && (v1->designated_port_id > v2->designated_port_id))) &&
            (v1->designated_bridge_id == v2->designated_bridge_id) && (v1->designated_port_id == v2->designated_port_id)) {
        VLOG_DBG("superior_same_des");
        return SUPERIOR_SAME_DES;
    }
    else if ((v1->root_bridge_id == v2->root_bridge_id) && (v1->root_path_cost == v2->root_path_cost) && 
            (v1->designated_bridge_id == v2->designated_bridge_id) && (v1->designated_port_id == v2->designated_port_id)) {
        VLOG_DBG("same");
        return SAME;
    }
    else {
        VLOG_DBG("not superior");
        return NOT_SUPERIOR;
    }
    
}
