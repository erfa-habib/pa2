
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;


typedef enum {
  connection_closed; /* may not be needed as connection is freed */
  connection_listen;
  connection_syn_sent;
  connection_syn_received;
  connection_established;
  connection_fin_wait_1;
  connection_fin_wait_2;
  connection_close_wait;
  connection_closing;
  connection_last_ack;
  connection_time_wait;
} tcp_connection_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  /* From the handout: 

       No need to track sequence numbers, or window values
       or ensure TCP packets are in proper order to the end hosts. 
       Keep only the information that is useful to the NAT for establishing or clearing mappings.
  */ 

  /* pair of sockets ? */ 
  /* what other state do we need to keep track of ? */
  tcp_connection_state state;
  struct sr_nat_connection *next;
};

/* Structure of a type8 ICMP header
 */
struct sr_icmp_t8_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_sum;
  /* added identifier and sequence number */
  uint16_t identifier;
  uint16_t sequence_num;
  uint16_t unused;
  uint16_t next_mtu;
  uint8_t data[ICMP_DATA_SIZE];

} __attribute__ ((packed)) ;
typedef struct sr_icmp_t8_hdr sr_icmp_t8_hdr_t;

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  /*my addition:
  add ICMP query timeout interval here
  tcp idle timeout
  tcp transitory idle timeout   */
  struct sr_nat_mapping *mappings;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


#endif
