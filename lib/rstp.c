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
 * Rapid Spanning Tree Protocol (IEEE 802.1D-2004) public interface.
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
#include "rstp-common.h"
#include "rstp-state-machines.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>
#include "byte-order.h"
#include "connectivity.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "packets.h"
#include "seq.h"
#include "unixctl.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(rstp);

static struct ovs_mutex mutex;
static struct list all_rstps__ = LIST_INITIALIZER(&all_rstps__);
static struct list *const all_rstps OVS_GUARDED_BY(mutex) = &all_rstps__;

/* Internal use only */
void set_port_id__(struct rstp_port *);
void update_port_enabled__(struct rstp_port *);
void set_bridge_priority__(struct rstp *);
void reinitialize_rstp__(struct rstp *);
int is_port_number_taken__(struct rstp *, int);

char *
get_id_string_from_uint8_t(uint8_t *m, int length)
{
    int i;
    char *string;
    
    string = malloc(length*3-1);
    if (length != 0) {
        sprintf(string,"%02X", m[0]);
        for (i = 1; i< length; i++) {
            sprintf(string+(i*3-1),":%02X", m[i]);
        }
        return string;
    } else {
        return NULL;
    }
}

const char *
rstp_state_name(enum rstp_state state)
{
    switch (state) {
    case RSTP_DISABLED:
        return "Disabled";
    case RSTP_LEARNING:
        return "Learning";
    case RSTP_FORWARDING:
        return "Forwarding";
    case RSTP_DISCARDING:
        return "Discarding";
    default:
        return "Unknown";
    }
}

const char *
rstp_port_role_name(enum rstp_port_role role)
{
    switch (role) {
    case ROLE_ROOT:
        return "Root";
    case ROLE_DESIGNATED:
        return "Designated";
    case ROLE_ALTERNATE:
        return "Alternate";
    case ROLE_BACKUP:
        return "Backup";
    case ROLE_DISABLED:
        return "Disabled";
    default:
        return "Unknown";
    }
}

struct rstp *
rstp_ref(const struct rstp *rstp_)
{
    struct rstp *rstp;
    
    rstp = CONST_CAST(struct rstp *, rstp_);
    if (rstp) {
        ovs_refcount_ref(&rstp->ref_cnt);
    }
    return rstp;
}

/* Frees RSTP struct */
void
rstp_unref(struct rstp *rstp)
{
    if (rstp && ovs_refcount_unref(&rstp->ref_cnt) == 1) {
        ovs_mutex_lock(&mutex);
        list_remove(&rstp->node);
        ovs_mutex_unlock(&mutex);
        free(rstp->name);
        free(rstp);
    }
}

/* Returns the port index in the port array.  */
int
rstp_port_index(const struct rstp_port *p)
{
    struct rstp *rstp;
    int index;
    
    ovs_mutex_lock(&mutex);
    rstp = p->rstp;
    ovs_assert(p >= rstp->ports && p < &rstp->ports[ARRAY_SIZE(rstp->ports)]);
    index = p - p->rstp->ports;
    ovs_mutex_unlock(&mutex);
    return index;
}

static void rstp_unixctl_tcn(struct unixctl_conn *, int argc,
                             const char *argv[], void *aux);
static int rstp_initialize_port(struct rstp_port *p);

/* Decrements the State Machines' timers. */
void
rstp_tick_timers(struct rstp *rstp)
{
    decrease_rstp_port_timers(rstp);
}

/* Processes an incoming BPDU. */
void
rstp_received_bpdu(struct rstp_port *p, const void *bpdu, size_t bpdu_size)
{
    process_received_bpdu(p, bpdu, bpdu_size);
}

void
rstp_init(void)
{
     unixctl_command_register("rstp/tcn", "[bridge]", 0, 1, rstp_unixctl_tcn,
                                     NULL);
}

/* Creates and returns a new RSTP instance that initially has no ports enabled. */
struct rstp *
rstp_create(const char *name, uint8_t *bridge_address,
        void (*send_bpdu)(struct ofpbuf *bpdu, int port_no, void *aux),
        void *aux)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct rstp *rstp;
    struct rstp_port *p;
    
    VLOG_DBG("Creating RSTP instance");
    if (ovsthread_once_start(&once)) {
        ovs_mutex_init_recursive(&mutex);
        ovsthread_once_done(&once);
    }

    ovs_mutex_lock(&mutex);
    rstp = xzalloc(sizeof *rstp);
    rstp->name = xstrdup(name);
    /* Set bridge address. */
    rstp_set_bridge_address(rstp, bridge_address);
    /* Set default parameters values. */
    rstp_set_bridge_priority(rstp, RSTP_DEFAULT_PRIORITY);
    rstp_set_bridge_ageing_time(rstp, RSTP_DEFAULT_AGEING_TIME);
    rstp_set_bridge_force_protocol_version(rstp, FPV_DEFAULT);
    rstp_set_bridge_forward_delay(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY);
    rstp_set_bridge_hello_time(rstp);
    rstp_set_bridge_max_age(rstp, RSTP_DEFAULT_BRIDGE_MAX_AGE);
    rstp_set_bridge_migrate_time(rstp);
    rstp_set_bridge_transmit_hold_count(rstp, RSTP_DEFAULT_TRANSMIT_HOLD_COUNT);
    rstp_set_bridge_times(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY,
                          RSTP_BRIDGE_HELLO_TIME, RSTP_DEFAULT_BRIDGE_MAX_AGE, 0);
    rstp->send_bpdu = send_bpdu;
    rstp->aux = aux;
    rstp->changes = false;
    rstp->begin = true;
    rstp->first_changed_port = &rstp->ports[ARRAY_SIZE(rstp->ports)];
    /* Initialize the ports array. */
    for (p = rstp->ports; p < &rstp->ports[ARRAY_SIZE(rstp->ports)]; p++) {
        p->rstp = rstp;
        rstp_initialize_port(p);
        rstp_port_set_state(p, RSTP_DISABLED);
    }
    ovs_refcount_init(&rstp->ref_cnt);
    list_push_back(all_rstps, &rstp->node);
    ovs_mutex_unlock(&mutex);
    VLOG_DBG("RSTP instance creation done");
    return rstp;
}

/* Called by rstp_set_bridge_address() and rstp_set_bridge_priority(),
   it updates the bridge priority vector according to the values passed by
   those setters. */
void
set_bridge_priority__(struct rstp *rstp)
{
    memcpy(rstp->bridge_priority.root_bridge_id, rstp->bridge_identifier, 8);
    memcpy(rstp->bridge_priority.designated_bridge_id, rstp->bridge_identifier, 8);
}

/* Sets the bridge address. */
void
rstp_set_bridge_address(struct rstp *rstp, uint8_t bridge_address[ETH_ADDR_LEN])
{
    struct rstp_port *p;
    
    VLOG_DBG("%s: set bridge address to %s",
             rstp->name, get_id_string_from_uint8_t(bridge_address, ETH_ADDR_LEN));
    ovs_mutex_lock(&mutex);
    memcpy(rstp->address, bridge_address, ETH_ADDR_LEN);
    memcpy(rstp->bridge_identifier+2, bridge_address, ETH_ADDR_LEN);
    set_bridge_priority__(rstp);

    /* [17.13] When the bridge address changes, recalculates all priority vectors. */
    for (p = rstp->ports; p < &rstp->ports[ARRAY_SIZE(rstp->ports)]; p++) {
        p->selected = 0;
        p->reselect = 1;
    }
    rstp->changes = true;
    updt_roles_tree(rstp);
    ovs_mutex_unlock(&mutex);
}

const char *
rstp_get_name(const struct rstp *rstp)
{
    char *name;
    
    ovs_mutex_lock(&mutex);
    name = rstp->name;
    ovs_mutex_unlock(&mutex);
    return name;
}

uint8_t *
rstp_get_bridge_id(const struct rstp *rstp)
{
    uint8_t *bridge_id;
    
    ovs_mutex_lock(&mutex);
    bridge_id = (uint8_t *) rstp->bridge_identifier;
    ovs_mutex_unlock(&mutex);
    return bridge_id;
}

/* Sets the bridge priority. */
void
rstp_set_bridge_priority(struct rstp *rstp, int new_priority)
{
    struct rstp_port *p;
    
    if (new_priority >= RSTP_MIN_PRIORITY && new_priority <= RSTP_MAX_PRIORITY) {
        VLOG_DBG("%s: set bridge priority to %d", rstp->name, (new_priority / 4096) * 4096);
        ovs_mutex_lock(&mutex);
        rstp->priority = (new_priority / 4096) * 4096;
        rstp->bridge_identifier[0] = (new_priority / 4096) << 4;
        set_bridge_priority__(rstp);

        /* [17.13] */
        for (p = rstp->ports; p < &rstp->ports[ARRAY_SIZE(rstp->ports)]; p++) {
            p->selected = 0;
            p->reselect = 1;
        }
        rstp->changes = true;
        updt_roles_tree(rstp);
        ovs_mutex_unlock(&mutex);
    }
}

/* Sets the bridge ageing time. */
void
rstp_set_bridge_ageing_time(struct rstp *rstp, int new_ageing_time)
{
    if (new_ageing_time >= RSTP_MIN_AGEING_TIME && new_ageing_time <= RSTP_MAX_AGEING_TIME) {
        VLOG_DBG("%s: set ageing time to %d", rstp->name, new_ageing_time);
        ovs_mutex_lock(&mutex);
        rstp->ageing_time = new_ageing_time;
        ovs_mutex_unlock(&mutex);
    }
}

/* Reinitializes RSTP when switching from RSTP mode to STP mode
   or vice versa. */
void
reinitialize_rstp__(struct rstp *rstp)
{
    char *name;
    uint8_t bridge_address[ETH_ADDR_LEN];
    void *send_bpdu;
    void *aux;
    struct ovs_refcount ref_count;
    struct list node;
    struct rstp_port *p;
    
    /* Copy name, bridge_address, ref_cnt, send_bpdu, aux, node */
    name = xstrdup(rstp->name);
    memcpy(&bridge_address, rstp->address, sizeof(rstp->address));
    memcpy(&ref_count, &rstp->ref_cnt, sizeof(struct ovs_refcount));
    send_bpdu = rstp->send_bpdu;
    aux = rstp->aux;
    node = rstp->node;
    /* stop and clear rstp */
    memset(rstp, 0, sizeof(struct rstp));

    /* Initialize rstp. */
    rstp->name = xstrdup(name);
    /* Set bridge address. */
    rstp_set_bridge_address(rstp, bridge_address);
    /* Set default parameters values. */
    rstp_set_bridge_priority(rstp, RSTP_DEFAULT_PRIORITY);
    rstp_set_bridge_ageing_time(rstp, RSTP_DEFAULT_AGEING_TIME);
    rstp_set_bridge_forward_delay(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY);
    rstp_set_bridge_hello_time(rstp);
    rstp_set_bridge_max_age(rstp, RSTP_DEFAULT_BRIDGE_MAX_AGE);
    rstp_set_bridge_migrate_time(rstp);
    rstp_set_bridge_transmit_hold_count(rstp, RSTP_DEFAULT_TRANSMIT_HOLD_COUNT);
    rstp_set_bridge_times(rstp, RSTP_DEFAULT_BRIDGE_FORWARD_DELAY,
                          RSTP_BRIDGE_HELLO_TIME, RSTP_DEFAULT_BRIDGE_MAX_AGE, 0);

    rstp->send_bpdu = send_bpdu;
    rstp->aux = aux;
    rstp->node = node;
    rstp->changes = false;
    rstp->begin = true;
    rstp->first_changed_port = &rstp->ports[ARRAY_SIZE(rstp->ports)];
    for (p = rstp->ports; p < &rstp->ports[ARRAY_SIZE(rstp->ports)]; p++) {
        p->rstp = rstp;
        rstp_initialize_port(p);
        rstp_port_set_state(p, RSTP_DISABLED);
    }
    memcpy(&rstp->ref_cnt, &ref_count, sizeof(struct ovs_refcount));
}

/* Sets the force protocol version parameter. */
void
rstp_set_bridge_force_protocol_version(struct rstp *rstp, enum rstp_force_protocol_version new_force_protocol_version)
{
    if (new_force_protocol_version != rstp->force_protocol_version &&
            (new_force_protocol_version == FPV_STP_COMPATIBILITY ||
             new_force_protocol_version == FPV_DEFAULT)) {
        VLOG_DBG("%s: set bridge Force Protocol Version to %d", rstp->name, new_force_protocol_version);
        ovs_mutex_lock(&mutex);
        /*
        [17.13] The Spanning Tree Protocol Entity shall be reinitialized, as
                specified by the assertion of BEGIN (17.18.1) in the state machine
                specification.
        */
        reinitialize_rstp__(rstp);
        rstp->force_protocol_version = new_force_protocol_version;
        if (rstp->force_protocol_version < 2) {
            rstp->stp_version = true;
            rstp->rstp_version = false;
        } else {
            rstp->stp_version = false;
            rstp->rstp_version = true;
        }
        rstp->changes = true;
        ovs_mutex_unlock(&mutex);
    }
}

/* Sets the bridge Hello Time parameter. */
void
rstp_set_bridge_hello_time(struct rstp *rstp)
{
    VLOG_DBG("%s: set RSTP Hello Time to %d", rstp->name, RSTP_BRIDGE_HELLO_TIME);
    /* 2 is the only acceptable value. */
    ovs_mutex_lock(&mutex);
    rstp->bridge_hello_time = RSTP_BRIDGE_HELLO_TIME;
    ovs_mutex_unlock(&mutex);
}

/* Sets the bridge max age parameter. */
void
rstp_set_bridge_max_age(struct rstp *rstp, int new_max_age)
{
    if (new_max_age >= RSTP_MIN_BRIDGE_MAX_AGE &&
        new_max_age <= RSTP_MAX_BRIDGE_MAX_AGE) {
        /* [17.13] */
        if ((2*(rstp->bridge_forward_delay - 1) >= new_max_age) &&
            (new_max_age >= 2*rstp->bridge_hello_time)) {
            VLOG_DBG("%s: set RSTP bridge Max Age to %d", rstp->name, new_max_age);
            ovs_mutex_lock(&mutex);
            rstp->bridge_max_age = new_max_age;
            rstp->bridge_times.max_age = new_max_age;
            ovs_mutex_unlock(&mutex);
        }
    }
}

/* Sets the bridge forward delay parameter. */
void
rstp_set_bridge_forward_delay(struct rstp *rstp, int new_forward_delay)
{
    if (new_forward_delay >= RSTP_MIN_BRIDGE_FORWARD_DELAY &&
            new_forward_delay <= RSTP_MAX_BRIDGE_FORWARD_DELAY) {
        if (2 * (new_forward_delay - 1) >= rstp->bridge_max_age) {
            VLOG_DBG("%s: set RSTP Forward Delay to %d", rstp->name, new_forward_delay);
            ovs_mutex_lock(&mutex);
            rstp->bridge_forward_delay = new_forward_delay;
            rstp->bridge_times.forward_delay = new_forward_delay;
            ovs_mutex_unlock(&mutex);
        }
    }
}

/* Sets the bridge transmit hold count parameter. */
void
rstp_set_bridge_transmit_hold_count(struct rstp *rstp, int new_transmit_hold_count)
{
    int port_no;
    
    if (new_transmit_hold_count >= RSTP_MIN_TRANSMIT_HOLD_COUNT &&
            new_transmit_hold_count <= RSTP_MAX_TRANSMIT_HOLD_COUNT) {
        VLOG_DBG("%s: set RSTP Transmit Hold Count to %d", rstp->name, new_transmit_hold_count);
        /* Resetting txCount on all ports [17.13]. */
        ovs_mutex_lock(&mutex);
        rstp->transmit_hold_count = new_transmit_hold_count;
        for (port_no = 0; port_no < RSTP_MAX_PORTS; port_no++) {
            struct rstp_port *p = rstp_get_port(rstp, port_no);
            p->tx_count=0;
        }
        ovs_mutex_unlock(&mutex);
    }
}

/* Sets the bridge migrate time parameter. */
void
rstp_set_bridge_migrate_time(struct rstp *rstp)
{
    VLOG_DBG("%s: set RSTP Migrate Time to %d", rstp->name, RSTP_MIGRATE_TIME);
    /* 3 is the only acceptable value */
    ovs_mutex_lock(&mutex);
    rstp->migrate_time = RSTP_MIGRATE_TIME;
    ovs_mutex_unlock(&mutex);
}

/* Sets the bridge times. */
void
rstp_set_bridge_times(struct rstp *rstp, int new_forward_delay, int new_hello_time, int new_max_age, int new_message_age)
{
    VLOG_DBG("%s: set RSTP times to (%d, %d, %d, %d)", rstp->name, new_forward_delay, new_hello_time, new_max_age, new_message_age);
    if (new_forward_delay >= RSTP_MIN_BRIDGE_FORWARD_DELAY && new_forward_delay <= RSTP_MAX_BRIDGE_FORWARD_DELAY)
        rstp->bridge_times.forward_delay = new_forward_delay;
    if (new_hello_time == RSTP_BRIDGE_HELLO_TIME)
        rstp->bridge_times.hello_time = new_hello_time;
    if (new_max_age >= RSTP_MIN_BRIDGE_MAX_AGE && new_max_age <= RSTP_MAX_BRIDGE_MAX_AGE)
        rstp->bridge_times.max_age = new_max_age;
    rstp->bridge_times.message_age = new_message_age;
}

/* Sets the port id, it is called by rstp_port_set_port_number() or
    rstp_port_set_priority(). */
void
set_port_id__(struct rstp_port *p) /* normally used when mutex is already locked */
{
    struct rstp *rstp;
    uint16_t temp;
    uint8_t *ptemp;

    rstp = p->rstp;
    /* [9.2.7] Port identifier. */
    temp = htons(p->port_number);
    ptemp = (uint8_t *)&temp;

    p->port_id[1] = ptemp[1];
    p->port_id[0] = ptemp[0] | p->priority;
    VLOG_DBG("%s: new RSTP port id %s", rstp->name, get_id_string_from_uint8_t(p->port_id, 2));
}

/* Sets the port priority. */
void
rstp_port_set_priority(struct rstp_port *rstp_port, int new_port_priority)
{
    struct rstp *rstp;
    
    rstp = rstp_port->rstp;
    if (new_port_priority >= RSTP_MIN_PORT_PRIORITY && new_port_priority  <= RSTP_MAX_PORT_PRIORITY) {
        VLOG_DBG("%s, port %u: set RSTP port priority to %d", rstp->name, rstp_port->port_number, new_port_priority);
        ovs_mutex_lock(&mutex);
        new_port_priority = new_port_priority - new_port_priority % RSTP_STEP_PORT_PRIORITY; /* floor */
        rstp_port->priority = new_port_priority;
        set_port_id__(rstp_port);
        rstp_port->selected = 0;
        rstp_port->reselect = 1;
        ovs_mutex_unlock(&mutex);
    }
}

/* Checks if a port number is already taken by an active port. */
int
is_port_number_taken__(struct rstp *rstp, int n)
{
    struct rstp_port *p;
    
    for (p = rstp->ports; p < &rstp->ports[ARRAY_SIZE(rstp->ports)]; p++) {
        if (p->port_number == n && p->rstp_state != RSTP_DISABLED) {
            VLOG_DBG("%s: port number %d already taken by port with state = %s", rstp->name, n,
                     rstp_state_name(p->rstp_state));
            return -1;
        }
    }
    return 0;
}

/* Sets the port number. */
void
rstp_port_set_port_number(struct rstp_port *rstp_port, uint16_t new_port_number)
{
    struct rstp *rstp;
    
    rstp = rstp_port->rstp;
    if (new_port_number >= 1 && new_port_number <= RSTP_MAX_PORT_NUMBER) {
        ovs_mutex_lock(&mutex);
        if (is_port_number_taken__(rstp_port->rstp,  new_port_number) != -1) {
            VLOG_DBG("%s: set new RSTP port number %d -> %d", rstp->name, rstp_port->port_number, new_port_number);
            rstp_port->port_number =  new_port_number;
            set_port_id__(rstp_port);
            /* [17.13] is not clear. I suppose that a port number change
               should trigger reselection like a port priority change. */
            rstp_port->selected = 0;
            rstp_port->reselect = 1;
        }
        ovs_mutex_unlock(&mutex);
    }
}

/* Converts the link speed to a port path cost [Table 17-3]. */
uint32_t
rstp_convert_speed_to_cost(unsigned int speed)
{
    uint32_t value;

    value = speed >=  10000000 ? 2 /* 10 Tb/s. */
        : speed >= 1000000 ? 20 /* 1 Tb/s. */
        : speed >= 100000 ? 200 /* 100 Gb/s. */
        : speed >= 10000 ? 2000 /* 10 Gb/s. */
        : speed >= 1000 ? 20000 /* 1 Gb/s. */
        : speed >= 100 ? 200000 /* 100 Mb/s. */
        : speed >= 10 ? 2000000 /* 10 Mb/s. */
        : speed >= 1 ? 20000000 /* 1 Mb/s. */
        : RSTP_DEFAULT_PORT_PATH_COST; /* 100 Mb/s. */

    return value;
}

/* Sets the port path cost. */
void
rstp_port_set_path_cost(struct rstp_port *rstp_port, uint32_t new_port_path_cost)
{
    struct rstp *rstp;
    
    rstp = rstp_port->rstp;
    if (new_port_path_cost >= RSTP_MIN_PORT_PATH_COST && new_port_path_cost <= RSTP_MAX_PORT_PATH_COST) {
        VLOG_DBG("%s, port %u, set RSTP port path cost to %d", rstp->name, rstp_port->port_number, new_port_path_cost);
        ovs_mutex_lock(&mutex);
        rstp_port->port_path_cost = new_port_path_cost;
        rstp_port->selected = 0;
        rstp_port->reselect = 1;
        ovs_mutex_unlock(&mutex);
    }
}

/* Gets the root path cost. */
uint8_t *
rstp_get_root_path_cost(const struct rstp *rstp)
{
    uint8_t *cost;
    
    ovs_mutex_lock(&mutex);
    cost = (uint8_t *) rstp->root_priority.root_path_cost;
    ovs_mutex_unlock(&mutex);
    return cost;
}

/* Returns true if something has happened to 'rstp' which necessitates flushing
 * the client's MAC learning table.
 */
bool
rstp_check_and_reset_fdb_flush(struct rstp *rstp)
{
    bool needs_flush;
    struct rstp_port *p, *end;

    needs_flush = false;
    
    ovs_mutex_lock(&mutex);
    end = &rstp->ports[ARRAY_SIZE(rstp->ports)];
    for (p = rstp->first_changed_port; p < end; p++) {
        if(p->fdb_flush == true) {
            needs_flush = true;
            /* fdb_flush should be reset by the filtering database
             * once the entries are removed if rstp_version is TRUE, and
             * immediately if stp_version is TRUE.*/
            p->fdb_flush = false;
        }
    }
    ovs_mutex_unlock(&mutex);
    return needs_flush;
}

/* Finds a port whose state has changed.  If successful, stores the port whose
 * state changed in '*portp' and returns true.  If no port has changed, stores
 * NULL in '*portp' and returns false. */
bool
rstp_get_changed_port(struct rstp *rstp, struct rstp_port **portp)
{
    struct rstp_port *end, *p;
    bool changed;
    
    changed = false;

    ovs_mutex_lock(&mutex);
    end = &rstp->ports[ARRAY_SIZE(rstp->ports)];
    for (p = rstp->first_changed_port; p < end; p++) {
        if (p->state_changed) {
            p->state_changed = false;
            rstp->first_changed_port = p + 1;
            *portp = p;
            changed = true;
            goto out;
        }
    }
    rstp->first_changed_port = end;
    *portp = NULL;
out:
    ovs_mutex_unlock(&mutex);
    return changed;
}

/* Returns the port in 'rstp' with index 'port_no', which must be between 0 and
 * RSTP_MAX_PORTS. */
struct rstp_port *
rstp_get_port(struct rstp *rstp, int port_no)
{
    struct rstp_port *port;
    
    ovs_mutex_lock(&mutex);
    ovs_assert(port_no >= 0 && port_no < ARRAY_SIZE(rstp->ports));
    port = &rstp->ports[port_no];
    ovs_mutex_unlock(&mutex);
    return port;
}

/* Updates the port_enabled parameter. */
void
update_port_enabled__(struct rstp_port *p)
{
    if (p->mac_operational && p->is_administrative_bridge_port == RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED) {
        p->port_enabled = true;
    } else {
        p->port_enabled = false;
    }
}

/* Sets the port MAC_Operational parameter [6.4.2]. */
void
rstp_port_set_mac_operational(struct rstp_port *p, bool new_mac_operational)
{
    struct rstp *rstp;

    ovs_mutex_lock(&mutex);
    rstp = p->rstp;
    p->mac_operational = new_mac_operational;
    update_port_enabled__(p);
    rstp->changes = true;
    move_rstp(rstp);
    ovs_mutex_unlock(&mutex);
}

/* Gets the port MAC_Operational parameter [6.4.2]. */
bool
rstp_port_get_mac_operational(struct rstp_port *p)
{
    bool value;
    
    ovs_mutex_lock(&mutex);
    value = p->mac_operational;
    ovs_mutex_unlock(&mutex);
    return value;
}

/* Sets the port Administrative Bridge Port parameter. */
void
rstp_port_set_administrative_bridge_port(struct rstp_port *p, uint8_t new_admin_port_state)
{
    if (new_admin_port_state == RSTP_ADMIN_BRIDGE_PORT_STATE_DISABLED ||
            new_admin_port_state == RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED) {
        p->is_administrative_bridge_port = new_admin_port_state;
        update_port_enabled__(p);
    }
}

/* Sets the port oper_point_to_point_mac parameter. */
void
rstp_port_set_oper_point_to_point_mac(struct rstp_port *p, uint8_t new_oper_p2p_mac)
{
    if (new_oper_p2p_mac == RSTP_OPER_P2P_MAC_STATE_DISABLED ||
            new_oper_p2p_mac == RSTP_OPER_P2P_MAC_STATE_ENABLED) {
        p->oper_point_to_point_mac = new_oper_p2p_mac;
        update_port_enabled__(p);
    }
}

/* Initializes a port with the defaults values for its parameters. */
static int
rstp_initialize_port(struct rstp_port *p)
OVS_REQUIRES(mutex)
{
    struct rstp *rstp;
    
    rstp = p->rstp;
    rstp_port_set_administrative_bridge_port(p, RSTP_ADMIN_BRIDGE_PORT_STATE_ENABLED);
    rstp_port_set_oper_point_to_point_mac(p, 1);
    rstp_port_set_path_cost(p, RSTP_DEFAULT_PORT_PATH_COST);
    rstp_port_set_priority(p, RSTP_DEFAULT_PORT_PRIORITY);
    rstp_port_set_port_number(p, rstp_port_index(p) + 1);
    rstp_port_set_path_cost(p, RSTP_DEFAULT_PORT_PATH_COST);
    rstp_port_set_auto_edge(p, true);

    p->port_receive_sm_state = PORT_RECEIVE_SM_INIT;
    p->port_protocol_migration_sm_state = PORT_PROTOCOL_MIGRATION_SM_INIT;
    p->bridge_detection_sm_state = BRIDGE_DETECTION_SM_INIT;
    p->port_transmit_sm_state = PORT_TRANSMIT_SM_INIT;
    p->port_information_sm_state = PORT_INFORMATION_SM_INIT;
    p->port_role_transition_sm_state = PORT_ROLE_TRANSITION_SM_INIT;
    p->port_state_transition_sm_state = PORT_STATE_TRANSITION_SM_INIT;
    p->topology_change_sm_state = TOPOLOGY_CHANGE_SM_INIT;

    p->uptime = 0;

    VLOG_DBG("%s: init RSTP port %s", rstp->name, get_id_string_from_uint8_t(p->port_id, 2));
    return 0;
}

/* Sets the port state. */
void
rstp_port_set_state(struct rstp_port *p, enum rstp_state state)
OVS_REQUIRES(mutex)
{
    struct rstp *rstp;
    
    rstp = p->rstp;
    VLOG_DBG("%s, port %u: set RSTP port state %s -> %s", rstp->name,
             p->port_number,
             rstp_state_name(p->rstp_state), rstp_state_name(state));

    if (state != p->rstp_state && !p->state_changed) {
        p->state_changed = true;
        if (p < p->rstp->first_changed_port) {
            p->rstp->first_changed_port = p;
        }
        seq_change(connectivity_seq_get());
    }
    p->rstp_state = state;
}


/* Enables RSTP on port 'p'.  The port will initially be in DISCARDING state. */
void
rstp_port_enable(struct rstp_port *p)
{
    struct rstp *rstp;
    
    ovs_mutex_lock(&mutex);
    rstp = p->rstp;
    if (p->rstp_state == RSTP_DISABLED) {
        rstp_initialize_port(p);
        rstp_port_set_state(p, RSTP_DISCARDING);
        p->rstp->ports_count++;
        VLOG_DBG("%s: enabling RSPT port %u", rstp->name, p->port_number);
        rstp->changes = true;
        move_rstp(rstp);
    }
    ovs_mutex_unlock(&mutex);
}

/* Disable RSTP on port 'p'. */
void
rstp_port_disable(struct rstp_port *p)
{
    struct rstp *rstp;
    
    ovs_mutex_lock(&mutex);
    rstp = p->rstp;
    if (p->rstp_state != RSTP_DISABLED) {
        VLOG_DBG("%s: disabling RSPT port %u", rstp->name, p->port_number);
        memset(p, 0, sizeof(struct rstp_port));
        p->rstp = rstp;
        rstp_initialize_port(p);
        rstp_port_set_state(p, RSTP_DISABLED);
        p->rstp->ports_count--;
        rstp->changes = true;
        move_rstp(rstp);
    }
    ovs_mutex_unlock(&mutex);
}

/* Sets the port Admin Edge parameter. */
void
rstp_port_set_admin_edge(struct rstp_port *rstp_port, bool new_admin_edge)
{
    struct rstp *rstp;
    
    rstp = rstp_port->rstp;
    if (rstp_port->admin_edge != new_admin_edge) {
        VLOG_DBG("%s, port %u: set RSTP Admin Edge to %d", rstp->name, rstp_port->port_number, new_admin_edge);
        ovs_mutex_lock(&mutex);
        rstp_port->admin_edge = new_admin_edge;
        ovs_mutex_unlock(&mutex);
    }
}

/* Sets the port Auto Edge parameter. */
void
rstp_port_set_auto_edge(struct rstp_port *rstp_port, bool new_auto_edge)
{
    struct rstp *rstp;
    
    rstp = rstp_port->rstp;
    if (rstp_port->auto_edge != new_auto_edge) {
        VLOG_DBG("%s, port %u: set RSTP Auto Edge to %d", rstp->name, rstp_port->port_number, new_auto_edge);
        ovs_mutex_lock(&mutex);
        rstp_port->auto_edge = new_auto_edge;
        ovs_mutex_unlock(&mutex);
    }
}

/* Sets the port mcheck parameter. */
void
rstp_port_set_mcheck(struct rstp_port *rstp_port, bool new_mcheck)
{
    struct rstp *rstp;
    
    ovs_mutex_lock(&mutex);
    rstp = rstp_port->rstp;
    if (new_mcheck == true && rstp_port->rstp->force_protocol_version >= 2) {
        rstp_port->mcheck = true;
        VLOG_DBG("%s, port %u: set RSTP mcheck to %d", rstp->name, rstp_port->port_number, new_mcheck);
    }
    ovs_mutex_unlock(&mutex);
}

/* Returns the designated bridge id. */
uint8_t *
rstp_get_designated_id(const struct rstp *rstp)
{
    uint8_t *designated_id;
    
    ovs_mutex_lock(&mutex);
    designated_id = (uint8_t *)rstp->root_priority.designated_bridge_id;
    ovs_mutex_unlock(&mutex);
    return designated_id;
}

/* Returns the root bridge id. */
uint8_t *
rstp_get_root_id(const struct rstp *rstp)
{
    uint8_t *root_id;
    
    ovs_mutex_lock(&mutex);
    root_id = (uint8_t *) rstp->root_priority.root_bridge_id;
    ovs_mutex_unlock(&mutex);
    return root_id;
}

/* Returns the designated port id. */
uint8_t *
rstp_get_designated_port_id(const struct rstp *rstp)
{
    uint8_t *designated_port_id;
    
    ovs_mutex_lock(&mutex);
    designated_port_id = (uint8_t *) rstp->root_priority.designated_port_id;
    ovs_mutex_unlock(&mutex);
    return designated_port_id;
}

/* Return the bridge port id. */
uint8_t *
rstp_get_bridge_port_id(const struct rstp *rstp)
{
    uint8_t *bridge_port_id;
    
    ovs_mutex_lock(&mutex);
    bridge_port_id =  (uint8_t *) rstp->root_priority.bridge_port_id;
    ovs_mutex_unlock(&mutex);
    return bridge_port_id;
}

/* Returns true if the bridge believes to the be root of the spanning tree,
 * false otherwise. */
bool
rstp_is_root_bridge(const struct rstp *rstp)
{
    bool is_root;

    ovs_mutex_lock(&mutex);
    if (memcmp(rstp->bridge_identifier, rstp->root_priority.designated_bridge_id, 8) == 0) {
        is_root = 1;
    } else {
        is_root = 0;
    }
    ovs_mutex_unlock(&mutex);
    return is_root;
}

/* Returns the bridge ID of the bridge currently believed to be the root. */
uint8_t *
rstp_get_designated_root(const struct rstp *rstp)
{
    uint8_t *designated_root;
    
    designated_root = xzalloc(sizeof(uint8_t [8]));
    ovs_mutex_lock(&mutex);
    memcpy(designated_root, rstp->root_priority.designated_bridge_id, 8);
    ovs_mutex_unlock(&mutex);
    return designated_root;
}

/* Returns the port connecting 'rstp' to the root bridge, or a null pointer if
 * there is no such port. */
struct rstp_port *
rstp_get_root_port(struct rstp *rstp)
{
    struct rstp_port *p;
    int i, ret_val;
    
    i = 0;
    ret_val = -1;
    ovs_mutex_lock(&mutex);
    for (p = rstp->ports; p < &rstp->ports[ARRAY_SIZE(rstp->ports)]; p++) {
        if (p->role == ROLE_ROOT && p->rstp_state != RSTP_DISABLED) {
             ret_val = i;
             p = &rstp->ports[ARRAY_SIZE(rstp->ports)];
        }
        i++;
    }
    ovs_mutex_unlock(&mutex);
    p = rstp->ports + ret_val;
    if (ret_val != -1) {
        return p;
    } else {
        return NULL;
    }
}

/* Returns the port ID for 'p'. */
uint8_t *
rstp_port_get_id(const struct rstp_port *p)
{
    uint8_t *port_id;
    
    ovs_mutex_lock(&mutex);
    port_id = (uint8_t *) p->port_id;
    ovs_mutex_unlock(&mutex);
    return port_id;
}

/* Returns the state of port 'p'. */
enum rstp_state
rstp_port_get_state(const struct rstp_port *p)
{
    enum rstp_state state;
    
    ovs_mutex_lock(&mutex);
    state = p->rstp_state;
    ovs_mutex_unlock(&mutex);
    return state;
}

/* Returns the role of port 'p'. */
enum rstp_port_role
rstp_port_get_role(const struct rstp_port *p)
{
    enum rstp_port_role role;
    
    ovs_mutex_lock(&mutex);
    role = p->role;
    ovs_mutex_unlock(&mutex);
    return role;
}

/* Retrieves BPDU transmit and receive counts for 'p'. */
void
rstp_port_get_counts(const struct rstp_port *p,
        int *tx_count, int *rx_count, int *error_count, int *uptime)
{
    ovs_mutex_lock(&mutex);
    *tx_count = p->tx_count;
    *rx_count = p->rx_rstp_bpdu_cnt;
    *error_count = p->error_count;
    *uptime = p->uptime;
    ovs_mutex_unlock(&mutex);
}

void
rstp_port_set_aux(struct rstp_port *p, void *aux)
{
    ovs_mutex_lock(&mutex);
    p->aux = aux;
    ovs_mutex_unlock(&mutex);
}

void *
rstp_port_get_aux(struct rstp_port *p)
{
    void *aux;
    
    ovs_mutex_lock(&mutex);
    aux = p->aux;
    ovs_mutex_unlock(&mutex);
    return aux;
}

/* Returns true if 'state' is one in which BPDU packets should be received
 * and transmitted on a port, false otherwise.
 */
 bool
 rstp_should_manage_bpdu(enum rstp_state state)
 {
     return (state == RSTP_DISCARDING || state == RSTP_LEARNING ||
         state == RSTP_FORWARDING);
 }

/* Returns true if 'state' is one in which packets received on a port should
 * be forwarded, false otherwise.
 *
 * Returns true if 'state' is RSTP_DISABLED, since presumably in that case the
 * port should still work, just not have RSTP applied to it. */
bool
rstp_forward_in_state(enum rstp_state state)
{
    if (state == RSTP_DISABLED || state == RSTP_FORWARDING) {
        return true;
    } else {
        return false;
    }
}

/* Returns true if 'state' is one in which MAC learning should be done on
 * packets received on a port, false otherwise.
 *
 * Returns true if 'state' is RSTP_DISABLED, since presumably in that case the
 * port should still work, just not have RSTP applied to it. */
bool
rstp_learn_in_state(enum rstp_state state)
{
    if (state == RSTP_DISABLED || state == RSTP_LEARNING || state == RSTP_FORWARDING) {
        return true;
    } else {
        return false;
    }
}

/* Unixctl. */
static struct rstp *
rstp_find(const char *name) OVS_REQUIRES(mutex)
{
    struct rstp *rstp;
    
    LIST_FOR_EACH(rstp, node, all_rstps) {
        if (!strcmp(rstp->name, name)) {
            return rstp;
        }
    }
    return NULL;
}

static void
rstp_unixctl_tcn(struct unixctl_conn *conn, int argc,
                 const char *argv[], void *aux OVS_UNUSED)
{
    ovs_mutex_lock(&mutex);
    if (argc > 1) {
        struct rstp *rstp = rstp_find(argv[1]);
        if (!rstp) {
            unixctl_command_reply_error(conn, "No such RSTP object");
            goto out;
        }
        rstp->changes = true;
        move_rstp(rstp);
    } else {
        struct rstp *rstp;
        LIST_FOR_EACH (rstp, node, all_rstps) {
            rstp->changes = true;
            move_rstp(rstp);
        }
    }
    unixctl_command_reply(conn, "OK");

out:
    ovs_mutex_unlock(&mutex);
}
