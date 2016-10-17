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
#include "sr_dumper.h"

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
		
		/* Check minimum length */
		if(len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))) {
			printf("Invalid IP Packet\n");
			return;
		}
		
		/* Get the ARP header from the packet */
		sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
		
		/* Check to make sure we are handling Ethernet format */
		if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
			printf ("Wrong hardware address format. Only Ethernet is supported.\n");
			return;
		}
		
		sr_handleARP(sr, ether_hdr, sr_ether_if, arp_hdr);
		
		break;
		
	case ethertype_ip:
		/* IP packet */
		
		printf("Received IP packet\n");
		
		/* Minimum length */
		if(len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))) {
			printf("Invalid IP Packet\n");
			return;
		}
  
        sr_handleIP(sr, packet, len, ether_hdr, sr_ether_if);
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
 
 /*
 
void sr_send_icmp_packet(struct sr_instance *sr,
        uint8_t *original_pkt,
        uint32_t tip,
        uint8_t icmp_type,
        uint8_t icmp_code)
{
	// Sends an ICMP packet //
    printf("Start sending icmp packet.\n");
    
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
                // icmp_pack_length = sizeof(sr_icmp_to_hdr_t);           //     
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
        // make icmp packet //
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
        // make ip packet //
        ip_packet->ip_hl = 4;
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
} */

void sr_send_icmp_packet(struct sr_instance *sr,
        sr_ip_hdr_t * ip_packet_hdr,
        uint8_t icmp_type,
        uint8_t icmp_code,
		sr_ethernet_hdr_t *ether_hdr,
		struct sr_if *ether_if) 
{
	/* Sends an ICMP packet */
	printf("Start sending icmp packet.\n");
    
	struct sr_rt * route = sr_search_route_table(sr, ip_packet_hdr->ip_src);
	
	if(route) {
		struct sr_if * local_if = sr_get_interface(sr, route->interface);
		
		if (!local_if) {
			perror("Invalid interface");
			return;
		}
		
		unsigned int icmp_len;
		uint8_t *icmp;

        switch(icmp_type)
        {
            case ICMP_ECHO: ;
                
				/* Get the ICMP header we received */
				icmp_hdr_t *icmp_hdr = (icmp_hdr_t *) ((uint8_t *)ip_packet_hdr + ip_packet_hdr->ip_hl*4);
				
				/* Get the ICMP length*/
				icmp_len = get_icmp_len(ICMP_ECHO, ICMP_ECHO, ip_packet_hdr);
				
				/* Check the ICMP checksum as well */
				if (ntohs(icmp_hdr->icmp_sum) != cksum(icmp_hdr, icmp_len)) {
					printf ("ICMP has an invalid checksum\n");
					return;
				}

				/* Create ICMP reply*/
				unsigned int icmp_reply_len = icmp_len + sizeof(sr_ethernet_hdr_t) + 
										sizeof(sr_ip_hdr_t);
				icmp = malloc(icmp_reply_len); /*allocate memory*/
										
				icmp_hdr_t *icmp_hdr_reply = (icmp_hdr_t *)(icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); /*create ICMP reply*/
				
				/* Set the Ethernet header information */
				set_eth_header(icmp, ether_hdr->ether_dhost, ether_hdr->ether_shost);
				
				/* Input all IP information here*/
				set_ip_header(icmp + sizeof(sr_ethernet_hdr_t), icmp_len, ip_protocol_icmp, ip_packet_hdr->ip_src, ip_packet_hdr->ip_dst);
				
				
				/* Set the ICMP header information and change the ICMP to reply,
				echo also has no code but we'll set to 0 by default*/
				create_icmp((uint8_t *)icmp_hdr_reply, ICMP_ECHO, ICMP_ECHO, ip_packet_hdr, icmp_len);
				
				/* Send the ICMP reply back */
				sr_send_packet(sr, icmp, icmp_reply_len, ether_if->name);
				
                break;
            case ICMP_DEST_UNREACHABLE: ;
				/* Otherwise we send a Dest, port unreachable ICMP back in the
				case that we get a TCP, UDP, or other protocol*/
				icmp_len = get_icmp_len(ICMP_DEST_UNREACHABLE, ICMP_DEST_PORT_UNREACHABLE_CODE, ip_packet_hdr);
				unsigned int len = icmp_len + sizeof(sr_ethernet_hdr_t) + 
										sizeof(sr_ip_hdr_t);
										
				icmp = malloc(len);
				
				/* Set the Ethernet header information */
				set_eth_header(icmp, ether_hdr->ether_dhost, ether_hdr->ether_shost);
				
				/* Set IP information */
				set_ip_header(icmp + sizeof(sr_ethernet_hdr_t), icmp_len, ip_protocol_icmp, ip_packet_hdr->ip_src, ip_packet_hdr->ip_dst);
				
				
				/* Set ICMP information */
				create_icmp(icmp, ICMP_DEST_UNREACHABLE, ICMP_DEST_PORT_UNREACHABLE_CODE, ip_packet_hdr, icmp_len);
				
				/* Send the ICMP reply back */
				sr_send_packet(sr, icmp, len, ether_if->name);
                break;
            case ICMP_TIME_EXCEEDED: ;
                break;
        }
		
        struct sr_rt *entry = sr_search_route_table(sr, ip_packet_hdr->ip_src);
        if (!entry) {
           return;
        }
		
		/*
        return sr_check_arp_send(sr, ip_packet_hdr, packet_length, entry, entry->interface);
		*/
    }
    return;
}

 void sr_handleIP(struct sr_instance* sr, uint8_t *packet, unsigned int len, sr_ethernet_hdr_t *ether_hdr, struct sr_if *ether_if) {
	/* Handles IP packets */ 
	
    /* Checking validation: TTL, checksum*/
	
	/* Retrieve IP header */
    sr_ip_hdr_t * ip_packet_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
	/* TTL */
    if (ntohs(ip_packet_hdr->ip_ttl) <= 1){
        sr_send_icmp_packet(sr, ip_packet_hdr, ICMP_TIME_EXCEEDED, ICMP_TIME_EXCEEDED_CODE, ether_hdr, ether_if);
		return;
    }
	
    /* Checksum */
    if(ntohs(ip_packet_hdr->ip_sum) != cksum(ip_packet_hdr, ip_packet_hdr->ip_hl*4))
    {
        printf("Invalid IP Packet\n");
        return;
    }
    
    /* Check destination */ 
    struct sr_if * local_interface = sr_search_interface_by_ip(sr, ip_packet_hdr->ip_dst);
	
    if (local_interface)
    {
        /* Destination is local interface */
        switch(ip_packet_hdr->ip_p)
        {				
			unsigned int icmp_len;
			uint8_t *icmp;
			
            case ip_protocol_icmp:
				/* ICMP is an echo request */
				printf ("ICMP ECHO REQUEST RECEIVED\n");
				
				/* Check length */
				if (len-sizeof(sr_ethernet_hdr_t) < (sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t))){
					perror("Invalid ICMP packet\n");
					return;
				}
				
				/* If echo */
				icmp_hdr_t *icmp_packet = (icmp_hdr_t *) ((uint8_t *)ip_packet_hdr + ip_packet_hdr->ip_hl*4);
				
				if(icmp_packet->icmp_type == ICMP_ECHO){
					sr_send_icmp_packet(sr, ip_packet_hdr, ICMP_ECHO, ICMP_ECHO, ether_hdr, ether_if);
				}
				
                break;
            default: ;
			
				/* Otherwise send dest unreachable */
				sr_send_icmp_packet(sr, ip_packet_hdr, ICMP_DEST_UNREACHABLE, ICMP_DEST_PORT_UNREACHABLE_CODE, ether_hdr, ether_if);
                
                break;
        }
    }
    else
    {
		/*
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
		*/
		return;
    }
}

void set_ip_header(uint8_t *packet, unsigned int len, uint8_t protocol, uint32_t src, uint32_t dst) {
	/* Sets header info for IP*/
	
    sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t *)packet;

	ip_packet->ip_tos = 0;
    ip_packet->ip_v = 4;
    ip_packet->ip_hl = sizeof(sr_ip_hdr_t)/4;
    ip_packet->ip_len = htons(sizeof(sr_ip_hdr_t) + len);
    ip_packet->ip_id = 0;
    ip_packet->ip_off = htons(IP_DF);
    ip_packet->ip_ttl = 64;
    ip_packet->ip_p = protocol;
    ip_packet->ip_src = src;
    ip_packet->ip_dst = dst;
    ip_packet->ip_sum = htons(cksum(ip_packet, 20));
}

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

void send_arp_request(struct sr_instance *sr, struct sr_arpreq *dest, struct sr_if *src) {
	/* Send an ARP request*/
	
	/* Send the ARP request to the Gateway. Has to have MAC address ff-ff-ff-ff (broadcast) */
	unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *packet = malloc(len);

	/* Set the ARP Header */
	set_arp_header(packet + sizeof(sr_ethernet_hdr_t), arp_op_request, src->addr, src->ip, (unsigned char *)BROADCAST, dest->ip);

	/* Set the Ethernet header */
	set_eth_header(packet, src->addr, (unsigned char *)BROADCAST);
	
	/* Send the packet */
	sr_send_packet(sr, packet, len, src->name);
	free(packet);
}

/*
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
        print_hdrs((uint8_t *)frame, frame_length); 
        return sr_send_packet(sr, (uint8_t *)frame, frame_length, interface);
    }
    else {
        struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache,
        ip_packet->ip_dst, (uint8_t *)frame, frame_length, interface);
        sr_handle_arpreq(sr, req);
        return 0;
    }
}
*/

/*---------------------------------------------------------------------
 * 
 * 						ICMP HANDLING
 *
 *---------------------------------------------------------------------*/

int get_icmp_len(uint8_t type, uint8_t code, sr_ip_hdr_t *orig_ip_hdr) {
	/* Get the length of the ICMP given it's type and code since it
	differs for every type */
	
	unsigned int icmp_pack_len;
	unsigned int ip_pack_len = min(orig_ip_hdr->ip_len - (orig_ip_hdr->ip_hl * 4), 8) + 
								(orig_ip_hdr->ip_hl * 4);
	
	switch(type)
	{
		case ICMP_DEST_UNREACHABLE:
			icmp_pack_len = sizeof(sr_icmp_t3_hdr_t);
			break;
		default: 
			/* Use the default ICMP header for the rest*/
			icmp_pack_len = sizeof(icmp_hdr_t);              
			break;
	}
	
	return icmp_pack_len + ip_pack_len;
	
}


void create_icmp(uint8_t *packet, uint8_t type, uint8_t code, sr_ip_hdr_t *orig_ip_hdr, unsigned int len){
	/* Creates the ICMP error based on code. 
	- Creates the IPv4 header, an 8-byte header
	- All types contain IP header
	- All types contain first 8 bytes of original datagram's data
	- Copies the old IP header into the ICMP data section
	- Performs a checksum
	*/
		
	/* Set the proper ICMP header and data */
	
	icmp_hdr_t *icmp_packet = (icmp_hdr_t *)(packet + 
			sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			
	/* Set the common parts of the ICMP packet */
	icmp_packet->icmp_type = type;
	icmp_packet->icmp_code = code;
	
	switch(type)
	{
		case ICMP_DEST_UNREACHABLE: ;
			/* next-hop MTU is the size of the packet that's too large for the IP MTU
			on the router interface.
			Tell it to expect the original packet size*/
			/* Convert from default type header to type 3 header */
			sr_icmp_t3_hdr_t *icmp3_packet = (sr_icmp_t3_hdr_t *)(packet + 
					sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					
			/* Set MTU */
			icmp3_packet->next_mtu = orig_ip_hdr->ip_len;
			
			/* Copy the first 8 bytes of the original datagram and the old IP header */
			memcpy(icmp3_packet->data, (uint8_t *)orig_ip_hdr, 
				min(ICMP_DATA_SIZE, orig_ip_hdr->ip_len));
				
			/* Checksum */
			icmp3_packet->icmp_sum = cksum((uint8_t *)icmp3_packet, len);
			break;
		default:
			/* Copy the first 8 bytes of the original datagram and the old IP header */
			memcpy(icmp_packet->data, (uint8_t *)orig_ip_hdr, 
				min(ICMP_DATA_SIZE, orig_ip_hdr->ip_len));
				
			/* Checksum */
			icmp_packet->icmp_sum = cksum((uint8_t *)icmp_packet, len);
	}
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

struct sr_rt * sr_search_route_table(struct sr_instance *sr,uint32_t ip)
{
	/* Searches the routing table for the node containing the IP address */
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