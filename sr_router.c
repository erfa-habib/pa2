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
        sr_handleIP(sr, packet, len, interface);
        break;
    
    default:
		/* if it's neither, just ignore it */
		printf("Incorrect protocol type received: %u\n", (unsigned)ether_hdr->ether_type);
        break;	
  }

}/* end sr_ForwardPacket */

void sr_handleARP(struct sr_instance* sr, sr_ethernet_hdr_t *ether_hdr, struct sr_if *sr_ether_if, sr_arp_hdr_t *arp_hdr) {
	/* Handles ARP requests and ARP replies */
	
	/* Opcode check: Request, reply, or neither */
	switch (ntohs(arp_hdr->ar_op)) {
		case arp_op_request: ;
			/* ARP request  */
			
			/* Check if the request is for this routers IP */
			/* Find the router the IP address corresponds to*/
			struct sr_if *router_if;
			
			for (router_if = sr->if_list; router_if != NULL; router_if = router_if->next) {
				if (router_if->ip == arp_hdr->ar_tip) {
					break;
				}
			}
			
			/* Send a reply back to the sender IP address */
			if (router_if) {
				unsigned int len = sizeof(sr_ethernet_hdr_t *) + sizeof(sr_arp_hdr_t *);
				uint8_t *packet = malloc(sizeof(uint8_t) * len);
				
				/* Set up reply with proper information */
				set_eth_header(packet, ether_hdr);
				
				/* Set up the ARP header */
				set_arp_header(packet+sizeof(sr_ethernet_hdr_t), router_if, arp_hdr);
								
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

void sr_handleIP(struct sr_instance* sr, 
        uint8_t *packet, 
        unsigned int len, 
        char * interface)
{
    /*   checking validation: minimum length, TTL, checksum*/
    //minimun length
    if(len<(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)))
    {
        printf("Invalid IP Packet\n");
        return;
    }
    sr_ip_hdr_t * ip_packet_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    //TTL
    if (ntohs(ip_packet_hdr->ip_ttl)<=1)
    {
        sr_send_icmp_packet(sr, (uint8_t *)ip_packet_hdr, ip_packet_hdr->ip_src, icmp_time_exceed, 0);
        return;
    }
    //Checksum
    uint8_t *data=(uint8_t *)(ip_packet_hdr+sizof(sr_ip_hdr_t));
    uint16_t compute_cksum=cksum(data, ip_packet_hdr->ip_hl*4);
    if(ntohs(ip_packet_hdr->ip_sum)!=compute_cksum)
    {
        printf("Invalid IP Packet\n");
        return;
    }
    
    
    //check destination 
    struct sr_if * local_interface = sr_search_interface_by_ip(sr, ip_packet_hdr->ip_dst);
    if (local_interface)
    {
        //destination is local interface
        switch(ip_packet_hdr->ip_p)
        {
            case ip_protocol_icmp:
                sr_handle_icmp(sr, ip_packet_hdr,len-sizeof(sr_ethernet_hdr_t,interface));
                break;
            default:
                sr_send_icmp_packet(sr, (unit8_t *)ip_packet_hdr, 
                        ip_packet_hdr->ip_src, icmp_destination_unreachalble,3);
                break;
        }
    }
    else
    {
        //destination is elsewhere: forward packet
        struc sr_rt *entry = sr_search_route_table(sr, ip_packet_hdr->ip_dst);
        if(entry)
        {
            ip_packet_hdr->ip_ttl -=1;
            ip_packet_hdr->ip_sum = 0;
            ip_packet_hdr->ip_sum = cksum(ip_packet_hdr, ip_packet_hdr->ip_hl*4);
            sr_check_arp_send(sr, ip_packet_hdr, len-sizeof(sr_ethernet_hdr_t),
                    entry, entry->interface);
        }
        else
        {
            sr_send_icmp_packet(sr, (uint8_t *)ip_packet_hdr,
                    ip_packet_hdr->ip_src, icmp_destination_unreachalble, 0);
        }
    }

}
void sr_handle_icmp(struct sr_instance * sr,
                uint8_t * packet,
                unsigned int len,
                char * interface)
{
    if(len < sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)){
        perror("Invalid icmp packet\n");
        return;
    }
    sr_ip_hdr_t * ip_packet = (sr_ip_hdr_t *)packet;
    sr_icmp_hdr_t * icmp_packet = (sr_icmp_hdr_t *)(packet + sizeof(sr_ip_hdr_t));
     /* response to echo request */
    if(icmp_packet->icmp_type == icmp_echo_request){
        sr_send_icmp_packet(sr, (uint8_t *)ip_packet, ip_packet->ip_src,icmp_echo_reply, 0);
    }
    return;
}

void sr_send_icmp_packet(struct sr_instance *sr,
        uint8_t *original_pkt,
        uint32_t tip,
        uint8_t icmp_type,
        uint8_t icmp_code)
{
    printf("Start sendign icmp packet.\n");
    
   struct sr_rt * route = sr_search_route_table(sr, tip);
   if(route)
   {
       struct sr_if * local_if = sr_get_interface(sr, route->interface);
       if(! local_if)
       {
       perror("Invalid interface");
       return -1;
       }

        unsigned int packet_length = sizeof(sr_ip_hdr_t);
        unsigned int ip_header_length = sizeof(sr_ip_hdr_t);
        unsigned int icmp_pack_length = 0;
        switch(icmp_type)
        {
            case icmp_echo_reply:
                icmp_pack_length = ntohs(((sr_ip_hdr_t *)original_pkt)->ip_len) - ((sr_ip_hdr_t *)original_pkt)->ip_hl * 4;
                /* icmp_pack_length = sizeof(sr_icmp_to_hdr_t);           */     
                break;
            case icmp_destination_unreachable:
                icmp_pack_length = sizeof(sr_icmp_t3_hdr_t);
                break;
            case icmp_time_exceed:
                icmp_pack_length = sizeof(sr_icmp_t11_hdr_t);
                break;
        }
    
        packet_length += icmp_pack_length;
        sr_ip_hdr_t * ip_packet = (sr_ip_hdr_t *)malloc(packet_length);
        memset(ip_packet, 0, packet_length);
        sr_icmp_t0_hdr_t * icmp_t0 = NULL;
        sr_icmp_t3_hdr_t * icmp_t3 = NULL;
        sr_icmp_t11_hdr_t * icmp_t11 = NULL;
        struct sr_icmp_hdr * icmp_common = (struct sr_icmp_hdr *)(((uint8_t *)ip_packet + ip_header_length));
        /* make icmp packet */
        icmp_common->icmp_type = icmp_type;
        icmp_common->icmp_code = icmp_code;
        switch(icmp_type)
        {
            case icmp_echo_reply:
                icmp_t0 = (sr_icmp_t0_hdr_t *)((uint8_t *)ip_packet +ip_header_length);
                icmp_t0->icmp_identifier = ((sr_icmp_t0_hdr_t *)(original_pkt +ip_header_length))->icmp_identifier;
                icmp_t0->icmp_seq = ((sr_icmp_t0_hdr_t *)(original_pkt +ip_header_length))->icmp_seq;
                icmp_t0->timestamp = ((sr_icmp_t0_hdr_t *)(original_pkt +ip_header_length))->timestamp;
                memcpy(icmp_t0->data, ((sr_icmp_t0_hdr_t *)(original_pkt + ip_header_length))->data, icmp_pack_length - 12);
                break;
            case icmp_destination_unreachable:
                icmp_t3 = (sr_icmp_t3_hdr_t *)((uint8_t *)ip_packet +ip_header_length);
                memcpy(icmp_t3->data, original_pkt, ICMP_DATA_SIZE);
                break;
            case icmp_time_exceed:
                icmp_t11 = (sr_icmp_t11_hdr_t *)((uint8_t *)ip_packet +
                ip_header_length);
                memcpy(icmp_t11->data, original_pkt, ICMP_DATA_SIZE);
                Debug("ICMP DATA:\n");
                Debug("data ip hl: %d\n", (((sr_ip_hdr_t *)original_pkt)->ip_hl));
                Debug("unused: %d\n", icmp_t11->unused);
                print_hdr_ip(icmp_t11->data);
                break;
        }
   
        icmp_common->icmp_sum = cksum((uint8_t *)icmp_common, icmp_pack_length);
        Debug("ICMP Header:\n");
        print_hdr_icmp((uint8_t *)icmp_common);
        /* make ip packet */
        ip_packet->ip_hl = 5;
        ip_packet->ip_v = 4;
        ip_packet->ip_tos = 0;
        ip_packet->ip_len = htons(packet_length);
        ip_packet->ip_id = 0;
        ip_packet->ip_off = htons(IP_DF);
        ip_packet->ip_ttl = 64;
        ip_packet->ip_p = ip_protocol_icmp;
        ip_packet->ip_sum = htons(0);
        ip_packet->ip_src = ((sr_ip_hdr_t *)original_pkt)->ip_dst;
        ip_packet->ip_dst = tip;
        ip_packet->ip_sum = cksum((uint8_t *)ip_packet, 20);
        Debug("icmp len: %d, ip len: %d\n", icmp_pack_length, packet_length);
        Debug("ICMP IP Packet:\n");
        print_hdr_ip((uint8_t *)ip_packet);
        struct sr_rt *entry = sr_search_route_table(sr, tip);
        if(!entry)
        {
           return -1;
        }
        return sr_check_arp_send(sr, ip_packet, packet_length, entry, entry->interface);
    }
    return -1; 
}


struct sr_if * sr_search_interface_by_ip(struct sr_instance *sr,uint32_t ip)
{
    struct sr_if * interface = sr->if_list;
    while(interface)
    {
        if(interface->ip == ip)
        {
            break;
        }
        interface = interface->next;
    }
    return interface;
}

struct sr_rt * sr_search_route_table(struct sr_instance *sr,uint32_t ip)
{
    struct sr_rt * entry = sr->routing_table;
    struct sr_rt * match = 0;
    while(entry){
        if((entry->dest.s_addr & entry->mask.s_addr) == (ip & entry->mask.s_addr)){
            if(! match || entry->mask.s_addr > match->mask.s_addr){
            match = entry;
            }
        }
        entry = entry->next;
    }
    return match;
}

int sr_check_arp_send(struct sr_instance *sr,
                sr_ip_hdr_t * ip_packet,
                unsigned int len,
                struct sr_rt * rt_entry,
                char * interface)
{
    struct sr_if * local_interface = sr_get_interface(sr, interface);
    if(!local_interface){
        perror("Invalid interface");
        return -1;
    }

    unsigned int frame_length = sizeof(sr_ethernet_hdr_t) + len;
    sr_ethernet_hdr_t * frame = (sr_ethernet_hdr_t *)malloc(frame_length);
    frame->ether_type = htons(ethertype_ip);
    memcpy((uint8_t *)frame + sizeof(sr_ethernet_hdr_t), ip_packet, len);
    memcpy(frame->ether_shost, local_interface->addr, ETHER_ADDR_LEN);
    uint32_t ip_to_arp = sr_search_interface_by_ip(sr, rt_entry->gw.s_addr) ?
        ip_packet->ip_dst : rt_entry->gw.s_addr;

    struct sr_arpentry * entry = sr_arpcache_lookup(
           &sr->cache, ip_to_arp);
    if(entry){
        memcpy(frame->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        free(entry);
        /*print_hdrs((uint8_t *)frame, frame_length);  */
        return sr_send_packet(sr, (uint8_t *)frame, frame_length, interface);
    }
    else {
        struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache,
        ip_packet->ip_dst, (uint8_t *)frame, frame_length, interface);
        sr_handle_arpreq(sr, req);
        return 0;
    }
}



void set_arp_header(uint8_t *packet, struct sr_if *router_if, sr_arp_hdr_t *arp_hdr) {
	/* Sets the fields in the arp header for arp packets */
	
	sr_arp_hdr_t *arp_hdr_reply = (sr_arp_hdr_t *)packet;
	
	arp_hdr_reply->ar_hrd = htons(arp_hrd_ethernet); /* hardware address */
	arp_hdr_reply->ar_pro = htons(ethertype_arp); /* ethernet type */
	arp_hdr_reply->ar_hln = ETHER_ADDR_LEN; /*len of hardware address */
	/* I'm not sure if this is the proper protocol address length */
	struct sr_ip_hdr *ip;
	arp_hdr_reply->ar_pln = ip->ip_hl; /* protocol address len */
	arp_hdr_reply->ar_op =  htons(arp_op_reply); /* opcode */
	memcpy (arp_hdr_reply->ar_sha, router_if->addr, ETHER_ADDR_LEN); /*sender hardware address */
	arp_hdr_reply->ar_sip = router_if->ip; /* sender ip address */
	memcpy (arp_hdr_reply->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN); /* target hardware address */
	arp_hdr_reply->ar_tip = arp_hdr->ar_sip; /* target ip address	*/
}

void set_eth_header(uint8_t *packet, sr_ethernet_hdr_t *ether_hdr) {
	/* Sets the fields in the ethernet header */
	
	/* Set up the Ethernet header */
	sr_ethernet_hdr_t *ether_arp_reply = (sr_ethernet_hdr_t *)packet;
	
	/* note: uint8_t is not 1 bit so use the size */
	memcpy(ether_arp_reply->ether_dhost, ether_hdr->ether_shost, (sizeof(uint8_t) * ETHER_ADDR_LEN)); /* dest ethernet address */
	memcpy(ether_arp_reply->ether_shost, ether_hdr->ether_dhost, (sizeof(uint8_t) * ETHER_ADDR_LEN)); /* source ethernet address */
	ether_arp_reply->ether_type = htons(ethertype_arp); /* packet type */
}
