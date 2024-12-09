/* See the corresponding blog post for details:
 * https://amodm.com/blog/2024/07/03/running-a-linux-router-on-macos
*/

#pragma once

#include <net/if_var.h>

#pragma pack(4)
struct ifbreq {
	char            ifbr_ifsname[IFNAMSIZ]; /* member if name */
	uint32_t        ifbr_ifsflags;          /* member if flags */
	uint32_t        ifbr_stpflags;          /* member if STP flags */
	uint32_t        ifbr_path_cost;         /* member if STP cost */
	uint8_t         ifbr_portno;            /* member if port number */
	uint8_t         ifbr_priority;          /* member if STP priority */
	uint8_t         ifbr_proto;             /* member if STP protocol */
	uint8_t         ifbr_role;              /* member if STP role */
	uint8_t         ifbr_state;             /* member if STP state */
	uint32_t        ifbr_addrcnt;           /* member if addr number */
	uint32_t        ifbr_addrmax;           /* member if addr max */
	uint32_t        ifbr_addrexceeded;      /* member if addr violations */
	uint8_t         pad[32];
};


struct ifbifconf {
	uint32_t	ifbic_len;	/* buffer size */
	union {
		caddr_t	ifbicu_buf;
		struct ifbreq *ifbicu_req;
#define	ifbic_buf	ifbic_ifbicu.ifbicu_buf
#define	ifbic_req	ifbic_ifbicu.ifbicu_req
	} ifbic_ifbicu;
};
