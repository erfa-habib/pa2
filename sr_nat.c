
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  struct sr_nat_mapping * mapping = nat->mappings;
  struct sr_nat_mapping * temp = NULL;
  while (mapping != NULL) {
        temp = mapping->next;
        free(mapping);
        mapping = temp;
  }

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

    // set these accordingly, using default for now
    int ICMP_timeout = 60;  
    int TCP_established_timeout = 7440;
    int TCP_transitory_timeout = 300; 

    /* handle periodic tasks here */
     /* go through each mapping and remove it if it is timed out */

    /* ICMP query time out interval */ 
    
    struct sr_nat_mapping * mapping = nat->mappings;
    struct sr_nat_mapping * prev_mapping = NULL;
    while (mapping != NULL) {
       if (mapping->type == nat_mapping_icmp) {
            if (curtime - mapping->last_updated >= ICMP_timeout) {
                  // mapping is timed out
                  // remove it from list and free it 
                  if (prev_mapping == NULL) { // first mapping in the table
                      nat->mappings = mapping->next;
                  } else {
                    prev_mapping->next = mapping->next;
                  }
                  free(mapping);
            }
       } else if (mapping->type == nat_mapping_tcp) {
          // need to check if transitory or established 
         // check last value in conns
       }
       prev_mapping = mapping;
       mapping = mapping->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));
   


   /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping * associated_mapping = nat->mappings; 
  while (associated_mapping != NULL) {
      if (associated_mapping->aux_ext == aux_ext && associated_mapping->type == type) {
          break;
      }
    associated_mapping = associated_mapping->next;
  }

  if (associated_mapping == NULL) {
    printf("no such mapping");
  }
  struct sr_nat_mapping *copy = NULL;
  
  /* do memcpy here? */
  if (associated_mapping) {
     copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
     memcpy(copy, associated_mapping, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping * associated_mapping = nat->mappings; 
  while (associated_mapping != NULL) {
      if ((associated_mapping->ip_int == ip_int) && (associated_mapping->aux_int == aux_int) && (associated_mapping->type == type)) {
          break;
      }
    associated_mapping = associated_mapping->next;
  }

  if (associated_mapping == NULL) {
    printf("no such mapping");
  }
   struct sr_nat_mapping *copy = NULL;
  /* do memcpy here? */
  if (associated_mapping) {
    copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
     memcpy(copy, associated_mapping, sizeof(struct sr_nat_mapping));
  }
  

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* Should we check whether mapping already exists before inserting it ? */ 
  int mapping_exists = 0;
  struct sr_nat_mapping * map_i = nat->mappings;
  while (map_i != NULL) {
        if (map_i->ip_int == ip_int && map_i->aux_int == aux_int && map_i->type == type) {
            mapping_exists = 1;
            printf("mapping exists");
            break; 
        }
        map_i = map_i->next;
  }
  
  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping)); 
  mapping->ip_int = ip_int; // set the internal ip address
  mapping->aux_int = aux_int; // set the internal port or icmp id
  mapping->type = type; // set type 
  mapping->last_updated = time(NULL); // set it to current time
  

  if (type == nat_mapping_icmp) {
  	/* for icmp, map internal address and internal identifier to a globally unique identifier */
    	 /* start at zero 
	 should we also just look through the ones that are icmp ? ? */
    	 uint16_t unique_id = 0; 
    	 int found_next_available_id = 0; 
  	    while (!found_next_available_id) {
		           struct sr_nat_mapping * this_mapping = nat->mappings;
       		     while (this_mapping != NULL) {
			             if (this_mapping->aux_ext == unique_id) {
 				           unique_id++;
				            break;
			         }
			         this_mapping = this_mapping->next;
		    }

       	 /* went through all of the mappings and didn't find the unique id */
      		  if (this_mapping == NULL) {
			             found_next_available_id = 1;
		        }
   	}
    mapping->conns = NULL; /* null for ICMP */
    mapping->aux_ext = unique_id;  /* set the unique id */
  } else if (type == nat_mapping_tcp) {
	/* need to make sure port we map to start from a specific number
	greater than 1023*/ 
        /* set mapping->conns */ 



  }
  
    /* set the external address to the external address of the nat  ? ? */ 
  // mapping->ip_ext = 

  /* add it to the list of mappings */
  if (!mapping_exists) {
       mapping->next = nat->mappings;
  }
 
 
  /* What else do we need to set in the mapping? */
   struct sr_nat_mapping *copy = NULL;
  /* look at arp_cache for this part */
  /* need to return copy for thread safety */ 
  if (mapping) {
     copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
     memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
