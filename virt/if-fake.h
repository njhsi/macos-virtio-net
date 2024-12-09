/* See the corresponding blog post for details:
 * https://amodm.com/blog/2024/07/03/running-a-linux-router-on-macos
*/

#pragma once

#include <net/if_var.h>

/* -----------------------------------------------------
 * Fake ethernet related headers.
 * https://opensource.apple.com/source/xnu/xnu-7195.81.3/bsd/net/if_fake_var.h.auto.html
 * -----------------------------------------------------
*/

/*
 * SIOCSDRVSPEC
 */
enum {
	IF_FAKE_S_CMD_NONE              = 0,
	IF_FAKE_S_CMD_SET_PEER          = 1,
	IF_FAKE_S_CMD_SET_MEDIA         = 2,
	IF_FAKE_S_CMD_SET_DEQUEUE_STALL = 3,
};

/*
 * SIOCGDRVSPEC
 */
enum {
	IF_FAKE_G_CMD_NONE              = 0,
	IF_FAKE_G_CMD_GET_PEER          = 1,
};

#define IF_FAKE_MEDIA_LIST_MAX  27

struct if_fake_media {
	int32_t         iffm_current;
	uint32_t        iffm_count;
	uint32_t        iffm_reserved[3];
	int32_t         iffm_list[IF_FAKE_MEDIA_LIST_MAX];
};

struct if_fake_request {
	uint64_t        iffr_reserved[4];
	union {
		char    iffru_buf[128];         /* stable size */
		struct if_fake_media    iffru_media;
		char    iffru_peer_name[IFNAMSIZ]; /* if name, e.g. "en0" */
		/*
		 * control dequeue stall. 0: disable dequeue stall, else
		 * enable dequeue stall.
		 */
		uint32_t        iffru_dequeue_stall;
	} iffr_u;
#define iffr_peer_name  iffr_u.iffru_peer_name
#define iffr_media      iffr_u.iffru_media
#define iffr_dequeue_stall      iffr_u.iffru_dequeue_stall
};
