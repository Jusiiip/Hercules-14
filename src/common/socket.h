/**
 * This file is part of Hercules.
 * http://herc.ws - http://github.com/HerculesWS/Hercules
 *
 * Copyright (C) 2012-2020 Hercules Dev Team
 * Copyright (C) Athena Dev Teams
 *
 * Hercules is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef COMMON_SOCKET_H
#define COMMON_SOCKET_H

#include "common/hercules.h"
#include "common/db.h"

#ifdef WIN32
#	include "common/winapi.h"
	typedef long in_addr_t;
#else
#	include <netinet/in.h>
#	include <sys/socket.h>
#	include <sys/types.h>
#endif

/* Forward Declarations */
struct hplugin_data_store;
struct config_setting_t;

#define FIFOSIZE_SERVERLINK 256*1024

// (^~_~^) Gepard Shield Start

#define  LICENSE_ID  2681722777
#define  CODE_VERSION  2016122701

#define  SESSION_CONST_1  0x53EB7BA0
#define  SESSION_CONST_2  0x4B6B8005

#define  ALGO_KEY_1  0xB6
#define  ALGO_KEY_2  0x46
#define  ALGO_KEY_3  0xD8

#define  DATA_HASH_CONST_1  0x6570A966
#define  DATA_HASH_CONST_2  0xF3C46506

// (^~_~^) Gepard Shield End

// (^~_~^) Gepard Shield Start

extern long long start_tick;
extern bool is_gepard_active;
extern unsigned int min_allowed_license_version;

#define MATRIX_SIZE     2048
#define KEY_SIZE        32

#define GEPARD_REASON_LENGTH 99
#define GEPARD_TIME_STR_LENGTH 24
#define GEPARD_RESULT_STR_LENGTH 100

struct gepard_crypt_unit
{
	unsigned int flag;
	unsigned char pos_1;
	unsigned char pos_2;
	unsigned char pos_3;
	unsigned char key[256];
};

struct gepard_info_data
{
	long long sync_tick;
	unsigned int unique_id;
	unsigned int license_version;
	unsigned char mac_address[6];
	unsigned int is_init_ack_received;
	unsigned short cs_packet_request_move;
	unsigned short cs_packet_action_request;
	unsigned short cs_packet_use_skill_to_id;
	unsigned short cs_packet_use_skill_to_ground;
};

enum gepard_server_types
{
	GEPARD_MAP      = 0xCCCC,
	GEPARD_LOGIN    = 0xAAAA,
};

enum gepard_info_type
{
	GEPARD_INFO_MESSAGE,
	GEPARD_INFO_MESSAGE_EXIT,
	GEPARD_INFO_INVALID_INIT_ACK,
	GEPARD_INFO_BANNED,
	GEPARD_INFO_OLD_LICENSE_VERSION,
};

enum gepard_packets
{
	CS_LOAD_END_ACK        = 0x007D,
	CS_WHISPER_TO          = 0x0096,

	CS_LOGIN_PACKET_1      = 0x0064,
	CS_LOGIN_PACKET_2      = 0x0277,
	CS_LOGIN_PACKET_3      = 0x02b0,
	CS_LOGIN_PACKET_4      = 0x01dd,
	CS_LOGIN_PACKET_5      = 0x01fa,
	CS_LOGIN_PACKET_6      = 0x027c,
	CS_LOGIN_PACKET_7      = 0x0825,

	SC_SET_UNIT_WALKING_1  = 0x07F7,
	SC_SET_UNIT_WALKING_2  = 0x0856,
	SC_SET_UNIT_WALKING_3  = 0x0914,
	SC_SET_UNIT_WALKING_4  = 0x09DB,
	SC_SET_UNIT_WALKING_5  = 0x09FD,

	SC_SET_UNIT_IDLE_1     = 0x07F9,
	SC_SET_UNIT_IDLE_2     = 0x0857,
	SC_SET_UNIT_IDLE_3     = 0x0915,
	SC_SET_UNIT_IDLE_4     = 0x09DD,
	SC_SET_UNIT_IDLE_5     = 0x09FF,

	SC_NOTIFY_TIME         = 0x007F,
	SC_STATE_CHANGE        = 0x0229,

	SC_MSG_STATE_CHANGE_1  = 0x0196,
	SC_MSG_STATE_CHANGE_2  = 0x043F,
	SC_MSG_STATE_CHANGE_3  = 0x0983,

	SC_WHISPER_FROM        = 0x0097,
	SC_WHISPER_SEND_ACK    = 0x0098,

	CS_GEPARD_SYNC         = 0x8285,
	CS_GEPARD_INIT_ACK     = 0xC392,

	SC_GEPARD_INIT         = 0x4753,
	SC_GEPARD_INFO         = 0xBCDE,
	SC_GEPARD_SETTINGS     = 0x5395,
};

enum gepard_internal_packets
{
	GEPARD_M2C_BLOCK_REQ   = 0x5000,
	GEPARD_C2M_BLOCK_ACK   = 0x5001,
	GEPARD_M2C_UNBLOCK_REQ = 0x5002,
	GEPARD_C2M_UNBLOCK_ACK = 0x5003,
};

void gepard_set_eof(int fd);
long long gepard_get_tick(void);
unsigned int gepard_get_unique_id(int fd);
struct socket_data* gepard_get_socket_data(int fd);
void gepard_init(struct socket_data* s, int fd, uint16 server_type);
void gepard_send_info(int fd, unsigned short info_type, const char* message);
bool gepard_process_cs_packet(int fd, struct socket_data* s, size_t packet_size);
void gepard_process_sc_packet(int fd, struct socket_data* s, size_t packet_size);

// (^~_~^) Gepard Shield End

// socket I/O macros
#define RFIFOHEAD(fd)
#define WFIFOHEAD(fd, size) sockt->wfifohead(fd, size)

#define RFIFOP(fd,pos) ((const void *)(sockt->session[fd]->rdata + sockt->session[fd]->rdata_pos + (pos)))
#define WFIFOP(fd,pos) ((void *)(sockt->session[fd]->wdata + sockt->session[fd]->wdata_size + (pos)))

#define RFIFOB(fd,pos) (*(const uint8*)RFIFOP((fd),(pos)))
#define WFIFOB(fd,pos) (*(uint8*)WFIFOP((fd),(pos)))
#define RFIFOW(fd,pos) (*(const uint16*)RFIFOP((fd),(pos)))
#define WFIFOW(fd,pos) (*(uint16*)WFIFOP((fd),(pos)))
#define RFIFOL(fd,pos) (*(const uint32*)RFIFOP((fd),(pos)))
#define WFIFOL(fd,pos) (*(uint32*)WFIFOP((fd),(pos)))
#define RFIFOQ(fd,pos) (*(const uint64*)RFIFOP((fd),(pos)))
#define WFIFOQ(fd,pos) (*(uint64*)WFIFOP((fd),(pos)))
#define RFIFOSPACE(fd) (sockt->session[fd]->max_rdata - sockt->session[fd]->rdata_size)
#define WFIFOSPACE(fd) (sockt->session[fd]->max_wdata - sockt->session[fd]->wdata_size)

#define RFIFOREST(fd)  (sockt->session[fd]->flag.eof ? 0 : sockt->session[fd]->rdata_size - sockt->session[fd]->rdata_pos)
#define RFIFOFLUSH(fd) \
	do { \
		if(sockt->session[fd]->rdata_size == sockt->session[fd]->rdata_pos){ \
			sockt->session[fd]->rdata_size = sockt->session[fd]->rdata_pos = 0; \
		} else { \
			sockt->session[fd]->rdata_size -= sockt->session[fd]->rdata_pos; \
			memmove(sockt->session[fd]->rdata, sockt->session[fd]->rdata+sockt->session[fd]->rdata_pos, sockt->session[fd]->rdata_size); \
			sockt->session[fd]->rdata_pos = 0; \
		} \
	} while(0)

#define WFIFOSET(fd, len)  (sockt->wfifoset(fd, len, true))
#define WFIFOSET2(fd, len)  (sockt->wfifoset(fd, len, false))
#define RFIFOSKIP(fd, len) (sockt->rfifoskip(fd, len))

/* [Ind/Hercules] */
#define RFIFO2PTR(fd) ((const void *)(sockt->session[fd]->rdata + sockt->session[fd]->rdata_pos))
#define RP2PTR(fd) RFIFO2PTR(fd)

/* [Hemagx/Hercules] */
#define WFIFO2PTR(fd) ((void *)(sockt->session[fd]->wdata + sockt->session[fd]->wdata_size))
#define WP2PTR(fd) WFIFO2PTR(fd)

// buffer I/O macros
static inline const void *RBUFP_(const void *p, int pos) __attribute__((const, unused));
static inline const void *RBUFP_(const void *p, int pos)
{
	return ((const uint8 *)p) + pos;
}
#define RBUFP(p,pos) RBUFP_(p, (int)(pos))
#define RBUFB(p,pos) (*(const uint8 *)RBUFP((p),(pos)))
#define RBUFW(p,pos) (*(const uint16 *)RBUFP((p),(pos)))
#define RBUFL(p,pos) (*(const uint32 *)RBUFP((p),(pos)))
#define RBUFQ(p,pos) (*(const uint64 *)RBUFP((p),(pos)))

static inline void *WBUFP_(void *p, int pos) __attribute__((const, unused));
static inline void *WBUFP_(void *p, int pos)
{
	return ((uint8 *)p) + pos;
}
#define WBUFP(p,pos) WBUFP_(p, (int)(pos))
#define WBUFB(p,pos) (*(uint8*)WBUFP((p),(pos)))
#define WBUFW(p,pos) (*(uint16*)WBUFP((p),(pos)))
#define WBUFL(p,pos) (*(uint32*)WBUFP((p),(pos)))
#define WBUFQ(p,pos) (*(uint64*)WBUFP((p),(pos)))

#define TOB(n) ((uint8)((n)&UINT8_MAX))
#define TOW(n) ((uint16)((n)&UINT16_MAX))
#define TOL(n) ((uint32)((n)&UINT32_MAX))


// Struct declaration
typedef int (*RecvFunc)(int fd);
typedef int (*SendFunc)(int fd);
typedef int (*ParseFunc)(int fd);

struct socket_data {
	struct {
		unsigned char eof : 1;
		unsigned char server : 1;
		unsigned char ping : 2;
		unsigned char validate : 1;
	} flag;

	uint32 client_addr; // remote client address

	uint8 *rdata, *wdata;
	size_t max_rdata, max_wdata;
	size_t rdata_size, wdata_size;
	size_t rdata_pos;
	uint32 last_head_size;
	time_t rdata_tick; // time of last recv (for detecting timeouts); zero when timeout is disabled
	time_t wdata_tick; // time of last send (for detecting timeouts);

	RecvFunc func_recv;
	SendFunc func_send;
	ParseFunc func_parse;

	void* session_data; // stores application-specific data related to the session

// (^~_~^) Gepard Shield Start
	struct gepard_info_data gepard_info;
	struct gepard_crypt_unit send_crypt;
	struct gepard_crypt_unit recv_crypt;
	struct gepard_crypt_unit sync_crypt;
// (^~_~^) Gepard Shield End

	struct hplugin_data_store *hdata; ///< HPM Plugin Data Store.
};

struct hSockOpt {
	unsigned int silent : 1;
	unsigned int setTimeo : 1;
};

/// Subnet/IP range in the IP/Mask format.
struct s_subnet {
	uint32 ip;
	uint32 mask;
};

/// A vector of subnets/IP ranges.
VECTOR_STRUCT_DECL(s_subnet_vector, struct s_subnet);

/// Use a shortlist of sockets instead of iterating all sessions for sockets
/// that have data to send or need eof handling.
/// Adapted to use a static array instead of a linked list.
///
/// @author Buuyo-tama
#define SEND_SHORTLIST

// Note: purposely returns four comma-separated arguments
#define CONVIP(ip) ((ip)>>24)&0xFF,((ip)>>16)&0xFF,((ip)>>8)&0xFF,((ip)>>0)&0xFF
#define MAKEIP(a,b,c,d) ((uint32)( ( ( (a)&0xFF ) << 24 ) | ( ( (b)&0xFF ) << 16 ) | ( ( (c)&0xFF ) << 8 ) | ( ( (d)&0xFF ) << 0 ) ))

/// Applies a subnet mask to an IP
#define APPLY_MASK(ip, mask) ((ip)&(mask))
/// Verifies the match between two IPs, with a subnet mask applied
#define SUBNET_MATCH(ip1, ip2, mask) (APPLY_MASK((ip1), (mask)) == APPLY_MASK((ip2), (mask)))

/**
 * Socket.c interface, mostly for reading however.
 **/
struct socket_interface {
	int fd_max;
	/* */
	time_t stall_time;
	time_t last_tick;

	const char *SOCKET_CONF_FILENAME;
	/* */
	uint32 addr_[16];   // ip addresses of local host (host byte order)
	int naddr_;   // # of ip addresses
	bool validate;

	struct socket_data **session;

	struct s_subnet_vector lan_subnets; ///< LAN subnets.
	struct s_subnet_vector trusted_ips; ///< Trusted IP ranges
	struct s_subnet_vector allowed_ips; ///< Allowed server IP ranges

	/* */
	void (*init) (void);
	void (*final) (void);
	/* */
	int (*perform) (int next);
	/* [Ind/Hercules] - socket_datasync */
	void (*datasync) (int fd, bool send);
	/* */
	int (*make_listen_bind) (uint32 ip, uint16 port);
	int (*make_connection) (uint32 ip, uint16 port, struct hSockOpt *opt);
	int (*realloc_fifo) (int fd, unsigned int rfifo_size, unsigned int wfifo_size);
	int (*realloc_writefifo) (int fd, size_t addition);
	int (*wfifoset) (int fd, size_t len, bool validate);
	void (*wfifohead) (int fd, size_t len);
	int (*rfifoskip) (int fd, size_t len);
	void (*close) (int fd);
	void (*validateWfifo) (int fd, size_t len);
	/* */
	bool (*session_is_valid) (int fd);
	bool (*session_is_active) (int fd);
	/* */
	void (*flush) (int fd);
	void (*flush_fifos) (void);
	int (*connect_client) (int listen_fd);
	void (*set_nonblocking) (int fd, unsigned long yes);
	void (*set_defaultparse) (ParseFunc defaultparse);
	/* hostname/ip conversion functions */
	uint32 (*host2ip) (const char* hostname);
	const char * (*ip2str) (uint32 ip, char *ip_str);
	uint32 (*str2ip) (const char* ip_str);
	/* */
	uint16 (*ntows) (uint16 netshort);
	/* */
	int (*getips) (uint32* ips, int max);
	/* */
	void (*eof) (int fd);

	uint32 (*lan_subnet_check) (uint32 ip, struct s_subnet *info);
	bool (*allowed_ip_check) (uint32 ip);
	bool (*trusted_ip_check) (uint32 ip);
	int (*net_config_read_sub) (struct config_setting_t *t, struct s_subnet_vector *list, const char *filename, const char *groupname);
	void (*net_config_read) (const char *filename);
};

#ifdef HERCULES_CORE
void socket_defaults(void);
#endif // HERCULES_CORE

HPShared struct socket_interface *sockt;

#endif /* COMMON_SOCKET_H */
