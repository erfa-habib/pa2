
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    
    
    /* TODO:
      if idle for timeout, remove from table 
      */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  sr_nat_mapping * associated_mapping = nat->mappings; 
  while (associated_mapping != NULL) {
      if (associated_mapping->ip_int == ip_int & associated_mapping->aux_int & associated_mapping->type == type) {
          break;
      }
    associated_mapping = associated_mapping->next;
  }
  
  struct sr_nat_mapping *copy = malloc(sizeof(sr_nat_mapping));
  /* do memcpy here? */

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));
  
  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = malloc(sizeof(sr_nat_mapping)); 
  mapping->ip_int = ip_int; // set the internal ip address
  mapping->aux_int = aux_int; // set the internal port or icmp id
  mapping->type = type; // set type 
  mapping->last_updated = time(null); // set it to current time
  

  if (type == nat_mapping_icmp) {
  	/* for icmp, map internal address and internal identifier to a globally unique identifier */
    	 /* start at zero */
    	 uint16_t unique_id = 0; 
    	 int found_next_available_id = 0; 
  	  while (!found_next_available_id) {
		sr_nat_mapping * this_mapping = nat->mappings;
       		 while (this_mapping != null) {
			if (this_mapping->aux_ext == unique_id) {
 				unique_id++;
				break;
			}
			this_mapping = this_mapping->next;
		}
       	 /* went through all of the mappings and didn't find the unique id */
      		  if (this_mapping == null) {
			found_next_available_id = 1;
		}
   	}
    mapping->conns = null; /* null for ICMP */ 
  } else if (type == nat_mapping_tcp) {
	/* need to make sure port we map to start from a specific number */



  }
  /* set the unique id */ 
  mapping->aux_ext = unique_id; 
  
 // mapping->conns = null; /* null for ICMP */ 
  /* set the external address to the external address of the nat  ? ? */ 
  // mapping->ip_ext = 

  /* add it to the list of mappings */
  mapping->next = nat->mappings;
 
  /* What else do we need to set in the mapping? */

  /* look at arp_cache for this part */

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}
