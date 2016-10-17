/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  
  /* Check if packet is smaller than it should be */
  if (sizeof(packet)/sizeof(uint8_t) != len) {
	printf("Received a corrupted packet.\n");
	return;
  } 
  
  /* Get the ethernet header from the packet */
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *) packet;
  
  /* Get the ethernet interface */
  struct sr_if *sr_ether_if = sr_get_interface(sr, interface);
  
  /* Check whether we found an interface corresponding to the name */
  if (sr_ether_if) {
	printf("Interface name: %s\n", sr_ether_if->name);
  } else {
	printf("Invalid interface found.\n");
	return;
  }
 
  /* Packet type check: IP, ARP, or neither */
  switch (ntohs(ether_hdr->ether_type)) {
	case ethertype_arp:
		/* ARP packet */
		
		printf("Received ARP packet\n");
		
		/* Get the ARP header from the packet */
		sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
		
		/* Check to make sure we are handling Ethernet format */
		if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
			printf ("Wrong hardware address format. Only Ethernet is supported.\n");
		} else {
			sr_handleARP(sr, ether_hdr, sr_ether_if, arp_hdr);
		}
		
		break;
		
	case ethertype_ip:
		/* IP packet */
		
		printf("Received IP packet\n");
        /* sr_handleIP(sr, packet, len, interface); */
        break;
    
    default:
		/* if it's neither, just ignore it */
		printf("Incorrect protocol type received: %u\n", (unsigned)ether_hdr->ether_type);
        break;	
  }

}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * 
 * 					ETHERNET HEADER 
 *
 *---------------------------------------------------------------------*/

void set_eth_header(uint8_t *packet, uint8_t *ether_shost, uint8_t *ether_dhost) {
	/* Sets the fields in the ethernet header */
	
	/* Set up the Ethernet header */
	sr_ethernet_hdr_t *ether_arp_reply = (sr_ethernet_hdr_t *)packet;
	
	/* note: uint8_t is not 1 bit so use the size */
	memcpy(ether_arp_reply->ether_dhost, ether_shost, (sizeof(uint8_t) * ETHER_ADDR_LEN)); /* dest ethernet address */
	memcpy(ether_arp_reply->ether_shost, ether_dhost, (sizeof(uint8_t) * ETHER_ADDR_LEN)); /* source ethernet address */
	ether_arp_reply->ether_type = htons(ethertype_arp); /* packet type */
}


/*---------------------------------------------------------------------
 * 
 * 					INTERNET PROTOCOL
 *
 *---------------------------------------------------------------------*/



/*---------------------------------------------------------------------
 * 
 * 					ADDRESS RESOLUTION PROTOCOL
 *
 *---------------------------------------------------------------------*/
 
 void sr_handleARP(struct sr_instance* sr, sr_ethernet_hdr_t *ether_hdr, struct sr_if *sr_ether_if, sr_arp_hdr_t *arp_hdr) {
	/* Handles ARP requests and ARP replies */
	
	/* Opcode check: Request, reply, or neither */
	switch (ntohs(arp_hdr->ar_op)) {
		case arp_op_request: ;
			/* ARP request  */
			
			/* Check if the request is for this routers IP */
			struct sr_if *router_if = sr_search_interface_by_ip(sr, arp_hdr->ar_tip);
			
			/* Send a reply back to the sender IP address */
			if (router_if) {
				unsigned int len = sizeof(sr_ethernet_hdr_t *) + sizeof(sr_arp_hdr_t *);
				uint8_t *packet = malloc(sizeof(uint8_t) * len);
				
				/* Set up reply with proper information */
				set_eth_header(packet, ether_hdr->ether_shost, ether_hdr->ether_dhost);
				
				/* Set up the ARP header */
				set_arp_header(packet+sizeof(sr_ethernet_hdr_t), arp_op_reply, router_if->addr, router_if->ip, arp_hdr->ar_sha, arp_hdr->ar_sip);
								
				/* Send packet and free the packet from memory */
				sr_send_packet(sr, packet, len, router_if->name);
				free(packet);
				
			}
			
			break;
		case arp_op_reply:
			/* ARP reply */
			
			printf("ARP reply to %lu\n", (unsigned long)arp_hdr->ar_sip);
			
			/* Queue the packet for this IP */
			struct sr_arpreq *cached;
			cached = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
		
			break;
		default:
			printf("Incorrect ARP opcode. Only ARP requests and replies are handled.\n");
	}
}

void set_arp_header(uint8_t *packet, unsigned short op, unsigned char *sha, uint32_t sip, unsigned char *tha, uint32_t tip) {
	/* Sets the fields in the arp header for arp packets */
	
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)packet;
	
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet); /* hardware address */
	arp_hdr->ar_pro = htons(ethertype_arp); /* ethernet type */
	arp_hdr->ar_hln = ETHER_ADDR_LEN; /*len of hardware address */
	/* I'm not sure if this is the proper protocol address length?? */
	arp_hdr->ar_pln = 4; /* protocol address len */
	arp_hdr->ar_op =  htons(op); /* opcode */
	memcpy (arp_hdr->ar_sha, sha, ETHER_ADDR_LEN); /*sender hardware address */
	arp_hdr->ar_sip = sip; /* sender ip address */
	memcpy (arp_hdr->ar_tha, tha, ETHER_ADDR_LEN); /* target hardware address */
	arp_hdr->ar_tip = tip; /* target ip address	*/
}

/*---------------------------------------------------------------------
 * 
 * 					SR UTILITY FUNCTIONS 
 *
 *---------------------------------------------------------------------*/

struct sr_if * sr_search_interface_by_ip(struct sr_instance *sr, uint32_t ip)
{
	/* Find the interface the IP address corresponds to*/
	struct sr_if *interface;
	
	for (interface = sr->if_list; interface != NULL; interface = interface->next) {
		if (interface->ip == ip) {
			break;
		}
	}
	
	return interface;
}