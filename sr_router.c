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

  /* fill in code here */
  
  /* Get the ethernet header from the packet */
  
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *) packet;
  
  /* Get the ethernet interface */
  
  struct sr_if *sr_ether_if = sr_get_interface(sr, interface);
  
  /* Packet type check: IP, ARP, or neither */
  
  switch (ntohs(ether_hdr->ether_type)) {
	case ethertype_arp:
		/* ARP packet */
		
		printf("Received ARP packet\n");
		
		sr_handleARP(sr, packet, ether_hdr, sr_ether_if, interface, len);
		
		break;
		
	case ethertype_ip:
		/* IP packet */
		
		printf("Received IP packet\n");
		
		
		/*check 3 things: minimum length, checksum and TTL*/
       if ((len-sizeof(sr_ethernet_hdr_t))>=20)
       {
		    /* Get the IP header from the packet */
		    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
            uint8_t *data = (uint8_t *)(ip_hdr+sizeof(sr_ip_hdr_t));
            uint16_t compute_cksum= cksum (data, (len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
            if (ip_hdr->ip_sum==compute_cksum && ntohs(ip_hdr->ip_ttl)>1)
            {
                /*hanle the right ip packet*/
                sr_hanleIP(sr, packet, ip_hdr);
            }
            else
            {
                /*just ignore it*/
                printf("Recieved INVALID IP packet\n")
            }
       }
       else
       {
            /*just ignore it*/
           printf("Recieved INVALID IP packet\n")
       }	
	
    default:
		/* if it's neither, just ignore it */
		printf("Incorrect protocol type received: %u\n", (unsigned)ether_hdr->ether_type);
	}
  }

}/* end sr_ForwardPacket */

void sr_handleARP(struct sr_instance* sr, uint8_t *packet, sr_ethernet_hdr_t *ether_hdr, struct sr_if *sr_ether_if, char* interface, unsigned int len) {
	/* Handles ARP requests and ARP replies */
	
	/* Get the ARP header from the packet */
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	
	/* Check to make sure we are handling Ethernet format */
	if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
		printf ("Wrong hardware address format. Only Ethernet is supported.\n");
		return;
	}
	
	/* Opcode check: Request, reply, or neither */
	switch (ntohs(arp_hdr->ar_op)) {
		case arp_op_request:
			/* ARP request  */
			
			break;
		case arp_op_reply:
			/* ARP reply */
			
			printf("ARP reply to %lu\n", (unsigned long)arp_hdr->ar_sip);
			
			/* Queue the packet for this IP */
			struct sr_arpreq *cached;
			cached = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
			
			/* Free the packet to reduce copies */
			free(packet);
		
			break;
		default:
			printf("Incorrect ARP opcode. Only ARP requests and replies are handled.\n");
	}
}

void sr_handleIP(struct sr_instance* sr, uint8_t *packet, sr_ip_hdr_t *ip_hdr)
{
    /*destination to one of the router's interface*/
    
    struct sr_if* if0 =sr->if_list;
    while(if0)
    {
        if(ntohs(ip_hdr->ip_dst)==if0->ip)//don't need ntohs here??
        {
            switch (if0->ip_p)
            {
                case ip_protocol_icmp:
                /* send reply*/

                break;
            default:
                /* send ICMP port unreachable*/
                break;
            }
            return;
        }
        else
        {
            if0= next_if;
            continue;
        }
    }
    /* if it is for elsewhere*/
    ip_hdr->ip_ttl--;
       
}
