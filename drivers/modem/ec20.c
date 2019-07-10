/*
 * Copyright (c) 2019 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_DOMAIN modem_ec20
#define LOG_LEVEL CONFIG_MODEM_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_DOMAIN);

#include <zephyr/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <zephyr.h>
#include <drivers/gpio.h>
#include <device.h>
#include <init.h>

#include <net/net_context.h>
#include <net/net_if.h>
#include <net/net_offload.h>
#include <net/net_pkt.h>
#include <net/socket_offload.h>
#include <net/socket.h>
#if defined(CONFIG_NET_IPV6)
#include "ipv6.h"
#endif
#if defined(CONFIG_NET_IPV4)
#include "ipv4.h"
#endif
#if defined(CONFIG_NET_UDP)
#include "udp_internal.h"
#endif

#include "modem_receiver.h"

#if !defined(CONFIG_MODEM_EC20_MANUAL_MCCMNO)
#define CONFIG_MODEM_EC20_MANUAL_MCCMNO ""
#endif

/* Uncomment the #define below to enable a hexdump of all incoming
 * data from the modem receiver
 */
//#define ENABLE_VERBOSE_MODEM_RECV_HEXDUMP	1

struct mdm_control_pinconfig {
	char *dev_name;
	u32_t pin;
};

#define PINCONFIG(name_, pin_) { \
	.dev_name = name_, \
	.pin = pin_ \
}

/* pin settings */
enum mdm_control_pins {
	MDM_POWER = 0,
	MDM_RESET,
	MAX_MDM_CONTROL_PINS,
};

static const struct mdm_control_pinconfig pinconfig[] = {
	/* MDM_POWER */
	PINCONFIG(DT_INST_0_QUECTEL_EC20_MDM_POWER_GPIOS_CONTROLLER,
		  DT_INST_0_QUECTEL_EC20_MDM_POWER_GPIOS_PIN),

	/* MDM_RESET */
	PINCONFIG(DT_INST_0_QUECTEL_EC20_MDM_RESET_GPIOS_CONTROLLER,
		  DT_INST_0_QUECTEL_EC20_MDM_RESET_GPIOS_PIN),
};

#define MDM_UART_DEV_NAME		DT_INST_0_QUECTEL_EC20_BUS_NAME

#define MDM_POWER_ENABLE		1
#define MDM_POWER_DISABLE		0
#define MDM_RESET_NOT_ASSERTED		1
#define MDM_RESET_ASSERTED		0

#define MDM_CMD_TIMEOUT			    K_SECONDS(5)
#define MDM_CMD_SEND_TIMEOUT		K_SECONDS(10)
#define MDM_CMD_READ_TIMEOUT		K_SECONDS(10)
#define MDM_CMD_CONN_TIMEOUT		K_SECONDS(31)

#define MDM_REGISTRATION_TIMEOUT	K_SECONDS(180)
#define MDM_PROMPT_CMD_DELAY		K_MSEC(10)

#define MDM_MAX_DATA_LENGTH		1500
#define MDM_MAX_BUF_LENGTH		1500

#define MDM_RECV_MAX_BUF		30
#define MDM_RECV_BUF_SIZE		255

#define MDM_MAX_SOCKETS			11
#define MDM_BASE_SOCKET_NUM		0

#define MDM_NETWORK_RETRY_COUNT		3
#define MDM_WAIT_FOR_RSSI_COUNT		10
#define MDM_WAIT_FOR_RSSI_DELAY		K_SECONDS(2)

#define BUF_ALLOC_TIMEOUT K_SECONDS(1)

#define CMD_HANDLER(cmd_, cb_) { \
	.cmd = cmd_, \
	.cmd_len = (u16_t)sizeof(cmd_)-1, \
	.func = on_cmd_ ## cb_ \
}

#define MDM_MANUFACTURER_LENGTH		10
#define MDM_MODEL_LENGTH		16
#define MDM_MIN_MODEL_LENGTH	5
#define MDM_REVISION_LENGTH		64
#define MDM_IMEI_LENGTH			16

#define DNS_ADDR_LENGTH			80

#define RSSI_TIMEOUT_SECS		30

#define SOCK_TYPE_TCP           "TCP"
#define SOCK_TYPE_UDP           "UDP"

NET_BUF_POOL_DEFINE(mdm_recv_pool, MDM_RECV_MAX_BUF, MDM_RECV_BUF_SIZE,
		    0, NULL);

static u8_t mdm_recv_buf[MDM_MAX_DATA_LENGTH];

/* RX thread structures */
K_THREAD_STACK_DEFINE(modem_rx_stack,
		       CONFIG_MODEM_EC20_RX_STACK_SIZE);
struct k_thread modem_rx_thread;

/* RX thread work queue */
K_THREAD_STACK_DEFINE(modem_workq_stack,
		      CONFIG_MODEM_EC20_RX_WORKQ_STACK_SIZE);
static struct k_work_q modem_workq;

static u8_t mdm_ok = 0;

struct ec20_socket {
    struct net_context *context;
	sa_family_t family;
	enum net_sock_type type;
	enum net_ip_protocol ip_proto;

	bool data_ready;

	/** semaphore */
	struct k_sem sem_write_ready;
	struct k_sem sem_read_ready;

	/* Read related parameters. */
	u8_t *p_recv_addr;
	size_t recv_max_len;
	u16_t bytes_read;
	bool is_in_reading;

	bool is_udp_opened;
	bool is_polled;
	bool in_use;
};

struct modem_iface_ctx {
	struct net_if *iface;
	u8_t mac_addr[6];

	/* GPIO PORT devices */
	struct device *gpio_port_dev[MAX_MDM_CONTROL_PINS];

	/* RX specific attributes */
	struct mdm_receiver_context mdm_ctx;

	/* socket data */
	struct ec20_socket sockets[MDM_MAX_SOCKETS];
	int last_socket_id;
	int last_error;

	/* semaphores */
	struct k_sem sem_response;
	struct k_sem sem_poll;

	/* RSSI work */
	struct k_delayed_work rssi_query_work;

	/* modem data */
	char mdm_manufacturer[MDM_MANUFACTURER_LENGTH];
	char mdm_model[MDM_MODEL_LENGTH];
	char mdm_revision[MDM_REVISION_LENGTH];
	char mdm_imei[MDM_IMEI_LENGTH];

	/* last DNS addr */
    char last_dns_addr[DNS_ADDR_LENGTH];

	int ev_creg;
};

struct cmd_handler {
	const char *cmd;
	u16_t cmd_len;
	void (*func)(struct net_buf **buf, u16_t len);
};

static struct modem_iface_ctx ictx;

static void modem_read_rx(struct net_buf **buf);
static void clean_socket(int id);

/*** Verbose Debugging Functions ***/
#if defined(ENABLE_VERBOSE_MODEM_RECV_HEXDUMP)
static inline void hexdump(const u8_t *packet, size_t length)
{
	char output[sizeof("xxxxyyyy xxxxyyyy")];
	int n = 0, k = 0;
	u8_t byte;

	while (length--) {
		if (n % 16 == 0) {
			printk(" %08X ", n);
		}

		byte = *packet++;

		printk("%02X ", byte);

		if (byte < 0x20 || byte > 0x7f) {
			output[k++] = '.';
		} else {
			output[k++] = byte;
		}

		n++;
		if (n % 8 == 0) {
			if (n % 16 == 0) {
				output[k] = '\0';
				printk(" [%s]\n", output);
				k = 0;
			} else {
				printk(" ");
			}
		}
	}

	if (n % 16) {
		int i;

		output[k] = '\0';

		for (i = 0; i < (16 - (n % 16)); i++) {
			printk("   ");
		}

		if ((n % 16) < 8) {
			printk(" "); /* one extra delimiter after 8 chars */
		}

		printk(" [%s]\n", output);
	}
}
#else
#define hexdump(...)
#endif

static u8_t socket_get(void) {
    for (int i = 0; i < MDM_MAX_SOCKETS; i++) {
		if (!ictx.sockets[i].in_use) {
			return i;
		}
	}

	return -ENOMEM;
}

static char *modem_sprint_ip_addr(const struct sockaddr *addr)
{
	static char buf[NET_IPV6_ADDR_LEN];

#if defined(CONFIG_NET_IPV6)
	if (addr->sa_family == AF_INET6) {
		return net_addr_ntop(AF_INET6, &net_sin6(addr)->sin6_addr,
				     buf, sizeof(buf));
	} else
#endif
#if defined(CONFIG_NET_IPV4)
	if (addr->sa_family == AF_INET) {
		return net_addr_ntop(AF_INET, &net_sin(addr)->sin_addr,
				     buf, sizeof(buf));
	} else
#endif
	{
		LOG_ERR("Unknown IP address family:%d", addr->sa_family);
		return NULL;
	}
}

/* Send an AT command with a series of response handlers */
static int send_at_cmd(const u8_t *data, struct k_sem *sem, int timeout) {
    int ret;

	ictx.last_error = 0;

	LOG_DBG("OUT: [%s]", log_strdup(data));
	mdm_receiver_send(&ictx.mdm_ctx, data, strlen(data));
	mdm_receiver_send(&ictx.mdm_ctx, "\r\n", 2);

	if (timeout == K_NO_WAIT) {
		return 0;
	}

	k_sem_reset(sem);
	ret = k_sem_take(sem, timeout);

	if (ret == 0) {
		ret = ictx.last_error;
	} else if (ret == -EAGAIN) {
		ret = -ETIMEDOUT;
	}

	return ret;
}

/*** NET_BUF HELPERS ***/

static bool is_crlf(u8_t c)
{
	if (c == '\n' || c == '\r') {
		return true;
	} else {
		return false;
	}
}

static void net_buf_skipcrlf(struct net_buf **buf)
{
	/* chop off any /n or /r */
	while (*buf && is_crlf(*(*buf)->data)) {
		net_buf_pull_u8(*buf);
		if (!(*buf)->len) {
			*buf = net_buf_frag_del(NULL, *buf);
		}
	}
}

static u16_t net_buf_findcrlf(struct net_buf *buf, struct net_buf **frag,
			      u16_t *offset)
{
	u16_t len = 0U, pos = 0U;

	while (buf && !is_crlf(*(buf->data + pos))) {
		if (pos + 1 >= buf->len) {
			len += buf->len;
			buf = buf->frags;
			pos = 0U;
		} else {
			pos++;
		}
	}

	if (buf && is_crlf(*(buf->data + pos))) {
		len += pos;
		*offset = pos;
		*frag = buf;
		return len;
	}

	return 0;
}

/*** MODEM RESPONSE HANDLERS ***/

static void on_cmd_atcmdinfo_manufacturer(struct net_buf **buf, u16_t len)
{
    strcpy(ictx.mdm_manufacturer, "Quectel");
	LOG_INF("Manufacturer: %s", log_strdup(ictx.mdm_manufacturer));
}

static void on_cmd_atcmdinfo_model(struct net_buf **buf, u16_t len)
{
	size_t out_len;
	struct net_buf *frag = NULL;
	u16_t offset;

	/* make sure model data is received */
	if (len < MDM_MIN_MODEL_LENGTH) {
		LOG_DBG("Waiting for data");
		/* wait for more data */
		k_sleep(K_MSEC(500));
		modem_read_rx(buf);
	}

	/* skip CR/LF */
	net_buf_skipcrlf(buf);
	if (!*buf) {
		LOG_DBG("Unable to find MODEL (net_buf_skipcrlf)");
		return;
	}

	len = net_buf_findcrlf(*buf, &frag, &offset);
	if (!frag) {
		LOG_DBG("Unable to find MODEL (net_buf_findcrlf)");
	}

	out_len = net_buf_linearize(ictx.mdm_model, sizeof(ictx.mdm_model) - 1,
				    *buf, 0, len);
	ictx.mdm_model[out_len] = 0;

	LOG_INF("Model: %s", log_strdup(ictx.mdm_model));
}

static void on_cmd_atcmdinfo_revision(struct net_buf **buf, u16_t len)
{
	size_t out_len;

	out_len = net_buf_linearize(ictx.mdm_revision,
				    sizeof(ictx.mdm_revision) - 1,
				    *buf, 0, len);
	ictx.mdm_revision[out_len] = 0;
	LOG_INF("Revision: %s", log_strdup(ictx.mdm_revision));
}

static void on_cmd_atcmdecho_nosock_imei(struct net_buf **buf, u16_t len)
{
	struct net_buf *frag = NULL;
	u16_t offset;
	size_t out_len;

	/* make sure IMEI data is received */
	if (len < MDM_IMEI_LENGTH) {
		LOG_DBG("Waiting for data");
		/* wait for more data */
		k_sleep(K_MSEC(500));
		modem_read_rx(buf);
	}

	/* skip CR/LF */
	net_buf_skipcrlf(buf);
	if (!*buf) {
		LOG_DBG("Unable to find IMEI (net_buf_skipcrlf)");
		return;
	}

	frag = NULL;
	len = net_buf_findcrlf(*buf, &frag, &offset);
	if (!frag) {
		LOG_DBG("Unable to find IMEI (net_buf_findcrlf)");
	}

	out_len = net_buf_linearize(ictx.mdm_imei, sizeof(ictx.mdm_imei) - 1,
				    *buf, 0, len);
	ictx.mdm_imei[out_len] = 0;

	LOG_INF("IMEI: %s", log_strdup(ictx.mdm_imei));
}

/* Handler: +CSQ: rssi[0],ber[1] */
static void on_cmd_atcmdinfo_rssi(struct net_buf **buf, u16_t len)
{
    int i = 0, rssi, param_count = 0;
	size_t value_size;
	char value[12];

	value_size = sizeof(value);
	while (*buf && len > 0 && param_count < 1) {
		i = 0;
		(void)memset(value, 0, value_size);

		while (*buf && len > 0 && i < value_size) {
			value[i] = net_buf_pull_u8(*buf);
			len--;
			if (!(*buf)->len) {
				*buf = net_buf_frag_del(NULL, *buf);
			}

			/* "," marks the end of each value */
			if (value[i] == ',') {
				value[i] = '\0';
				break;
			}

			i++;
		}

		if (i == value_size) {
			i = -1;
			break;
		}

		param_count++;
	}

	if (param_count == 1 && i > 0) {
		rssi = atoi(value);
		if (rssi >= 0 && rssi <= 97) {
			ictx.mdm_ctx.data_rssi = -140 + rssi;
		} else {
			ictx.mdm_ctx.data_rssi = -1000;
		}

		LOG_INF("RSSI: %d", ictx.mdm_ctx.data_rssi);
		return;
	}

	LOG_WRN("Bad format found for RSSI");
	ictx.mdm_ctx.data_rssi = -1000;
}

/* Handler: OK */
static void on_cmd_sockok(struct net_buf **buf, u16_t len)
{
    k_sem_give(&ictx.sem_response);
	LOG_INF("OK");
}

static void on_cmd_socksend(struct net_buf **buf, u16_t len)
{
    struct ec20_socket *sock = NULL;
	sock = &ictx.sockets[ictx.last_socket_id];
    k_sem_give(&sock->sem_write_ready);
}

static void on_cmd_sockwrote(struct net_buf **buf, u16_t len)
{
    struct ec20_socket *sock = NULL;
	sock = &ictx.sockets[ictx.last_socket_id];
    k_sem_give(&sock->sem_write_ready);
	k_sem_give(&ictx.sem_response);
}

/* Handler: ERROR */
static void on_cmd_sockexterror(struct net_buf **buf, u16_t len)
{
    char value[8];
	size_t out_len;

	out_len = net_buf_linearize(value, sizeof(value) - 1, *buf, 0, len);
	value[out_len] = 0;
	ictx.last_error = -atoi(value);
	LOG_ERR("+CME %d", ictx.last_error);
	k_sem_give(&ictx.sem_response);
}

/* Handler: +QICLOSE: <socket_id> */
/* Handler: +QIURC: "closed",<socket_id> */
static void on_cmd_socknotifyclose(struct net_buf **buf, u16_t len)
{
	char value[2];
	int id;

	/* make sure only a single digit is picked up for socket_id */
	value[0] = net_buf_pull_u8(*buf);
	len--;
	value[1] = 0;

	id = atoi(value);
	if (id < MDM_BASE_SOCKET_NUM) {
		return;
	}

    clean_socket(id);
}

static void on_cmd_socknotifydata(struct net_buf **buf, u16_t len)
{
    char value[2];
    struct ec20_socket *sock = NULL;
    int id;

    /* make sure only a single digit is picked up for socket_id */
    value[0] = net_buf_pull_u8(*buf);
    len--;
    value[1] = 0;

    id = atoi(value);
    ictx.last_socket_id = id;
    sock = &ictx.sockets[id];
    k_sem_give(&sock->sem_read_ready);
}

/* Handler: +QIURC: "dnsgip","<addr>" */
static void on_cmd_getaddr(struct net_buf **buf, u16_t len)
{
	size_t out_len;

	out_len = net_buf_linearize(ictx.last_dns_addr, sizeof(ictx.last_dns_addr) - 1, *buf, 0, len);
    // remove the last double quote
	ictx.last_dns_addr[out_len - 1] = 0;

    k_sem_give(&ictx.sem_response);
}

static void on_cmd_write_ready(struct net_buf **buf, u16_t len)
{
	struct ec20_socket *socket;
	size_t out_len;
	char buffer[20];
	char *temp[2];
	u8_t id;

	out_len = net_buf_linearize(buffer, sizeof(buffer) - 1, *buf, 0, len);
	buffer[out_len] = 0;
	id = atoi(strtok(buffer, ","));
	socket = &ictx.sockets[id];
	temp[0] = strtok(NULL, ",");
	temp[1] = strtok(NULL, ",");
	if (temp[1] == NULL) {
		/* URC respond ready to write like '0,1' */
		LOG_DBG("Write ready.");
	} else {
		/* URC respond ready to accept write like '0,10,0' */
		LOG_DBG("Write data accept ready.");
	}
	k_sem_give(&socket->sem_write_ready);
}

static void on_cmd_read_ready(struct net_buf **buf, u16_t len)
{
	struct ec20_socket *sock;
	char buffer[10];
	u16_t bytes_read, i = 0;
    size_t out_len;
	u8_t id, c = 0U;

    id = ictx.last_socket_id;

	sock = &ictx.sockets[id];
	k_sem_give(&sock->sem_read_ready);

    out_len = net_buf_linearize(buffer, sizeof(buffer), *buf, 0, len);
    buffer[out_len] = 0;
    bytes_read = atoi(buffer);
    LOG_DBG("Reported %d bytes to be read. len: %d %s", bytes_read, len, log_strdup(buffer));

    while (i < len) {
        i++;
        net_buf_pull_u8(*buf);
    }

    i = 0;
    while (i < bytes_read) {
        if (!(*buf)->len) {
			*buf = net_buf_frag_del(NULL, *buf);
		}

        modem_read_rx(buf);
        if (*buf) {
            out_len = (*buf)->len;
            while (out_len) {
                out_len--;
                c = net_buf_pull_u8(*buf);
                sock->p_recv_addr[i] = c;
                i++; 
            }
        }
        k_yield();
    }
     sock->p_recv_addr[bytes_read] = 0;

    /*
    while(i < bytes_read) {
        c = net_buf_pull_u8(*buf);
        sock->p_recv_addr[i] = c;
        if (!(*buf)->len) {
            *buf = net_buf_frag_del(NULL, *buf);
        }
    }
    sock->p_recv_addr[i] = 0;

    */
    sock->bytes_read = bytes_read;
    sock->is_in_reading = false;
	//k_sem_give(&sock->sem_read_ready);
}

static void on_cmd_socket_error(struct net_buf **buf, u16_t len)
{
	char buffer[10];
	size_t out_len;

	out_len = net_buf_linearize(buffer, sizeof(buffer) - 1, *buf, 0, len);
	buffer[out_len] = 0;
	strtok(buffer, ",");
	strtok(buffer, ",");
	ictx.last_error = -atoi(strtok(buffer, ","));
	LOG_ERR("+CME %d", ictx.last_error);
	k_sem_give(&ictx.sem_response);
}

static int net_buf_ncmp(struct net_buf *buf, const u8_t *s2, size_t n)
{
	struct net_buf *frag = buf;
	u16_t offset = 0U;

	while ((n > 0) && (*(frag->data + offset) == *s2) && (*s2 != '\0')) {
		if (offset == frag->len) {
			if (!frag->frags) {
				break;
			}
			frag = frag->frags;
			offset = 0U;
		} else {
			offset++;
		}

		s2++;
		n--;
	}

	return (n == 0) ? 0 : (*(frag->data + offset) - *s2);
}

static inline struct net_buf *read_rx_allocator(s32_t timeout, void *user_data)
{
	return net_buf_alloc((struct net_buf_pool *)user_data, timeout);
}

static void modem_read_rx(struct net_buf **buf)
{
	u8_t uart_buffer[MDM_RECV_BUF_SIZE];
	size_t bytes_read = 0;
	int ret;
	u16_t rx_len;

	/* read all of the data from mdm_receiver */
	while (true) {
		ret = mdm_receiver_recv(&ictx.mdm_ctx,
					uart_buffer,
					sizeof(uart_buffer),
					&bytes_read);
		if (ret < 0 || bytes_read == 0) {
			/* mdm_receiver buffer is empty */
			break;
		}

		hexdump(uart_buffer, bytes_read);

		/* make sure we have storage */
		if (!*buf) {
			*buf = net_buf_alloc(&mdm_recv_pool, BUF_ALLOC_TIMEOUT);
			if (!*buf) {
				LOG_ERR("Can't allocate RX data! "
					    "Skipping data!");
				break;
			}
		}

		rx_len = net_buf_append_bytes(*buf, bytes_read, uart_buffer,
					      BUF_ALLOC_TIMEOUT,
					      read_rx_allocator,
					      &mdm_recv_pool);

		if (rx_len < bytes_read) {
			LOG_ERR("Data was lost! read %u of %u!",
				    rx_len, bytes_read);
		}
	}
}

/* RX thread */
static void modem_rx(void)
{
	struct net_buf *rx_buf = NULL, *swap_buf = NULL;
	struct net_buf *frag = NULL;
	int i;
	u16_t offset, len;

	static const struct cmd_handler handlers[] = {
		/* MODEM Information */
		CMD_HANDLER("AT+CGSN", atcmdecho_nosock_imei),
		CMD_HANDLER("Quectel", atcmdinfo_manufacturer),
		CMD_HANDLER("Revision: ", atcmdinfo_revision),
		CMD_HANDLER("AT+CGMM", atcmdinfo_model),
		CMD_HANDLER("+CSQ: ", atcmdinfo_rssi),

		/* SOLICITED SOCKET RESPONSES */
		CMD_HANDLER("OK", sockok),
		CMD_HANDLER("+QIGETERROR", sockexterror),

		/* UNSOLICITED RESPONSE CODES */
		CMD_HANDLER("+QICLOSE: ", socknotifyclose),
		CMD_HANDLER("+QIURC: \"closed\",", socknotifyclose),
		CMD_HANDLER("+QIURC: \"recv\",", socknotifydata),
		CMD_HANDLER("+QIURC: \"dnsgip\",\"", getaddr),
		CMD_HANDLER("SEND OK", sockwrote),

        /* SOCKET OPERATION RESPONSES */
		CMD_HANDLER("+QIOPEN: ", write_ready),
		CMD_HANDLER("+QIRD: ", read_ready),
		CMD_HANDLER("AT+QISEND=", socksend),
		CMD_HANDLER("+QIURC \"error\",", socket_error),
	};

    char rx_tmp[128];
	while (true) {
		/* wait for incoming data */
		k_sem_take(&ictx.mdm_ctx.rx_sem, K_FOREVER);

		modem_read_rx(&rx_buf);

		while (rx_buf) {
			net_buf_skipcrlf(&rx_buf);
			if (!rx_buf) {
				break;
			}

			frag = NULL;
			len = net_buf_findcrlf(rx_buf, &frag, &offset);
			if (!frag) {
				break;
			}

            /*
            if (len != offset) {
                swap_buf = net_buf_clone(rx_buf, 10);
                rx_buf = net_buf_frag_del(NULL, rx_buf);
                modem_read_rx(&rx_buf);
                net_buf_add_mem(swap_buf, rx_buf->data, rx_buf->len);
                net_buf_unref(rx_buf);
                rx_buf = swap_buf;
            }
            */

            memcpy(rx_tmp, rx_buf->data, rx_buf->len);
            rx_tmp[rx_buf->len] = 0;
            if (rx_buf->len > 40) {
                LOG_DBG("<-- (len:%d) %s", rx_buf->len, log_strdup(rx_tmp + 20));
            } else {
                LOG_DBG("<-- (len:%d) %s", rx_buf->len, log_strdup(rx_tmp));
            }

			/* look for matching data handlers */
			for (i = 0; i < ARRAY_SIZE(handlers); i++) {
				if (net_buf_ncmp(rx_buf, handlers[i].cmd,
						 handlers[i].cmd_len) == 0) {
					/* found a matching handler */
					LOG_DBG("MATCH %s (len:%u)",
						    handlers[i].cmd, len);

					/* skip cmd_len */
					rx_buf = net_buf_skip(rx_buf,
							handlers[i].cmd_len);

					/* locate next cr/lf */
					frag = NULL;
					len = net_buf_findcrlf(rx_buf,
							       &frag, &offset);
					if (!frag) {
						break;
					}

					/* call handler */
					if (handlers[i].func) {
						handlers[i].func(&rx_buf, len);
					}

					frag = NULL;
					/* make sure buf still has data */
					if (!rx_buf) {
						break;
					}

					/*
					 * We've handled the current line
					 * and need to exit the "search for
					 * handler loop".  Let's skip any
					 * "extra" data and look for the next
					 * CR/LF, leaving us ready for the
					 * next handler search.  Ignore the
					 * length returned.
					 */
					(void)net_buf_findcrlf(rx_buf,
							       &frag, &offset);
					break;
				}
			}

			if (frag && rx_buf) {
				/* clear out processed line (buffers) */
				while (frag && rx_buf != frag) {
					rx_buf = net_buf_frag_del(NULL, rx_buf);
				}

				net_buf_pull(rx_buf, offset);
			}
		}

		/* give up time if we have a solid stream of data */
		k_yield();
	}
}

static int modem_pin_init(void)
{
	LOG_INF("Setting Modem Pins");

    mdm_ok = 0;
	gpio_pin_configure(ictx.gpio_port_dev[MDM_RESET],
			  pinconfig[MDM_RESET].pin, GPIO_DIR_OUT);
	gpio_pin_configure(ictx.gpio_port_dev[MDM_POWER],
			  pinconfig[MDM_POWER].pin, GPIO_DIR_OUT);

	LOG_DBG("MDM_RESET_PIN -> NOT_ASSERTED");
	gpio_pin_write(ictx.gpio_port_dev[MDM_RESET],
		       pinconfig[MDM_RESET].pin, MDM_RESET_NOT_ASSERTED);

	LOG_DBG("MDM_POWER_PIN -> DISABLE");
	gpio_pin_write(ictx.gpio_port_dev[MDM_POWER],
		       pinconfig[MDM_POWER].pin, MDM_POWER_DISABLE);
	/* make sure module is powered off */
	k_sleep(K_SECONDS(12));

	LOG_DBG("MDM_POWER_PIN -> ENABLE");
	gpio_pin_write(ictx.gpio_port_dev[MDM_POWER],
		       pinconfig[MDM_POWER].pin, MDM_POWER_ENABLE);
	k_sleep(K_SECONDS(1));

	LOG_DBG("MDM_POWER_PIN -> DISABLE");
	gpio_pin_write(ictx.gpio_port_dev[MDM_POWER],
		       pinconfig[MDM_POWER].pin, MDM_POWER_DISABLE);
	k_sleep(K_SECONDS(1));

	LOG_DBG("MDM_POWER_PIN -> ENABLE");
	gpio_pin_write(ictx.gpio_port_dev[MDM_POWER],
		       pinconfig[MDM_POWER].pin, MDM_POWER_ENABLE);
	k_sleep(K_SECONDS(10));

	gpio_pin_configure(ictx.gpio_port_dev[MDM_POWER],
			  pinconfig[MDM_POWER].pin, GPIO_DIR_IN);

    mdm_ok = 1;
	LOG_INF("... Done!");

	return 0;
}

static void modem_rssi_query_work(struct k_work *work)
{
	int ret;

	/* query modem RSSI */
	ret = send_at_cmd("AT+CSQ", &ictx.sem_response, MDM_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("AT+CSQ ret:%d", ret);
	}

	/* re-start RSSI query work */
	k_delayed_work_submit_to_queue(&modem_workq,
				       &ictx.rssi_query_work,
				       K_SECONDS(RSSI_TIMEOUT_SECS));
}

static void modem_reset(void)
{
	int ret = 0, retry_count = 0, counter = 0;

	/* bring down network interface */
	atomic_clear_bit(ictx.iface->if_dev->flags, NET_IF_UP);

    send_at_cmd("AT+QPOWD", &ictx.sem_response, MDM_CMD_TIMEOUT);

restart:
	/* stop RSSI delay work */
	k_delayed_work_cancel(&ictx.rssi_query_work);

	modem_pin_init();

	LOG_INF("Waiting for modem to respond");

	/* Give the modem a while to start responding to simple 'AT' commands.
	 * Also wait for CSPS=1 or RRCSTATE=1 notification
	 */
	ret = -1;
	while (counter++ < 50 && ret < 0) {
		k_sleep(K_SECONDS(2));
		ret = send_at_cmd("AT", &ictx.sem_response, MDM_CMD_TIMEOUT);
		if (ret < 0 && ret != -ETIMEDOUT) {
			break;
		}
	}

	if (ret < 0) {
		LOG_ERR("MODEM WAIT LOOP ERROR: %d", ret);
		goto error;
	}

	/* echo on */
	ret = send_at_cmd("ATE1", &ictx.sem_response, MDM_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("ATE1 ret:%d", ret);
		goto error;
	}

	/* query modem info */
	LOG_INF("Querying modem information");
	ret = send_at_cmd("ATI", &ictx.sem_response, MDM_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("ATI ret:%d", ret);
		goto error;
	}
    k_sleep(K_SECONDS(1));

	ret = send_at_cmd("AT+CGMM", &ictx.sem_response, MDM_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("AT+CGMM ret:%d", ret);
		goto error;
	}

	/* query modem IMEI */
	ret = send_at_cmd("AT+CGSN", &ictx.sem_response, MDM_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("AT+CGSN ret:%d", ret);
		goto error;
	}

	/* HEX receive data mode */
	ret = send_at_cmd("AT+QICFG=\"dataformat\",0,0", &ictx.sem_response, MDM_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("AT+QICFG=1 ret:%d", ret);
	}

    /* Use AT+COPS? to query current Network Operator */
	ret = send_at_cmd("AT+COPS?", &ictx.sem_response, MDM_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("AT+COPS? ret:%d", ret);
		goto error;
	}

    /* register operator automatically */
    ret = send_at_cmd("AT+COPS=0,0", &ictx.sem_response, MDM_REGISTRATION_TIMEOUT);

	if (ret < 0) {
		LOG_ERR("AT+COPS ret:%d", ret);
		goto error;
	}

	LOG_INF("Waiting for network");

	/* wait for +CREG: 1 notification (20 seconds max) */
	counter = 0;
    // TODO change counter back to 20
	while (counter++ < 10 && ictx.ev_creg != 1) {
		k_sleep(K_SECONDS(1));
	}

	/* query modem RSSI */
	modem_rssi_query_work(NULL);
	k_sleep(MDM_WAIT_FOR_RSSI_DELAY);

	counter = 0;
	/* wait for RSSI < 0 and > -1000 */
	while (counter++ < MDM_WAIT_FOR_RSSI_COUNT &&
	       (ictx.mdm_ctx.data_rssi >= 0 ||
		ictx.mdm_ctx.data_rssi <= -1000)) {
		/* stop RSSI delay work */
		k_delayed_work_cancel(&ictx.rssi_query_work);
		modem_rssi_query_work(NULL);
		k_sleep(MDM_WAIT_FOR_RSSI_DELAY);
	}

	if (ictx.mdm_ctx.data_rssi >= 0 || ictx.mdm_ctx.data_rssi <= -1000) {
		retry_count++;
		if (retry_count >= MDM_NETWORK_RETRY_COUNT) {
			LOG_ERR("Failed network init.  Too many attempts!");
			ret = -ENETUNREACH;
			goto error;
		}

		LOG_ERR("Failed network init.  Restarting process.");
		goto restart;
	}


    ret = send_at_cmd("AT+QIACT=1", &ictx.sem_response, MDM_CMD_TIMEOUT);
    if (ret < 0) {
		LOG_ERR("AT+QIACT=1 ret:%d", ret);
	}
    k_sleep(K_SECONDS(1));

	LOG_INF("Network is ready.");

	/* Set iface up */
	net_if_up(ictx.iface);

error:
	return;
}

static int modem_init(struct device *dev)
{
	int i, ret = 0;

	ARG_UNUSED(dev);

	/* check for valid pinconfig */
	__ASSERT(ARRAY_SIZE(pinconfig) == MAX_MDM_CONTROL_PINS,
	       "Incorrect modem pinconfig!");

    (void)memset(&ictx, 0, sizeof(ictx));
	k_sem_init(&ictx.sem_response, 0, 1);
	k_sem_init(&ictx.sem_poll, 0, 1);
    for (i = 0; i < MDM_MAX_SOCKETS; i++) {
		k_sem_init(&ictx.sockets[i].sem_write_ready, 0, 1);
		k_sem_init(&ictx.sockets[i].sem_read_ready, 0, 1);
	}
    ictx.last_socket_id = 0;

	/* initialize the work queue */
	k_work_q_start(&modem_workq,
		       modem_workq_stack,
		       K_THREAD_STACK_SIZEOF(modem_workq_stack),
		       K_PRIO_COOP(7));

	ictx.last_socket_id = MDM_BASE_SOCKET_NUM - 1;

	/* setup port devices and pin directions */
	for (i = 0; i < MAX_MDM_CONTROL_PINS; i++) {
		ictx.gpio_port_dev[i] =
				device_get_binding(pinconfig[i].dev_name);
		if (!ictx.gpio_port_dev[i]) {
			LOG_ERR("gpio port (%s) not found!",
				    pinconfig[i].dev_name);
			return -ENODEV;
		}
	}

	/* Set modem data storage */
	ictx.mdm_ctx.data_manufacturer = ictx.mdm_manufacturer;
	ictx.mdm_ctx.data_model = ictx.mdm_model;
	ictx.mdm_ctx.data_revision = ictx.mdm_revision;
	ictx.mdm_ctx.data_imei = ictx.mdm_imei;

	ret = mdm_receiver_register(&ictx.mdm_ctx, MDM_UART_DEV_NAME,
				    mdm_recv_buf, sizeof(mdm_recv_buf));
	if (ret < 0) {
		LOG_ERR("Error registering modem receiver (%d)!", ret);
		goto error;
	}

	/* start RX thread */
	k_thread_create(&modem_rx_thread, modem_rx_stack,
			K_THREAD_STACK_SIZEOF(modem_rx_stack),
			(k_thread_entry_t) modem_rx,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);

	/* init RSSI query */
	k_delayed_work_init(&ictx.rssi_query_work, modem_rssi_query_work);

    // TODO
    // set DNS

    // TODO
    //modem_reset();
	net_if_up(ictx.iface);

error:
	return ret;
}

static void clean_socket(int id) {
    struct ec20_socket *sock = NULL;
    sock = &ictx.sockets[id];
	sock->context = NULL;
	sock->in_use = false;
	k_sem_reset(&sock->sem_read_ready);
	k_sem_reset(&sock->sem_write_ready);
}

static int ec20_socket(int family,int type, int proto)
{
    u8_t id;
	struct ec20_socket *sock = NULL;

    if (family != AF_INET) {
		return -ENOTSUP;
	}

    if (type != SOCK_STREAM && type != SOCK_DGRAM) {
		return -ENOTSUP;
	}

    id = socket_get();
	if (id < 0) {
		return -ENOMEM;
	}

    sock = &ictx.sockets[id];
	sock->ip_proto = proto;
	sock->family = family;
	sock->ip_proto = proto;

	sock->in_use = true;

    return id;
}

static int ec20_close(int id) {
	char buffer[sizeof("AT+QICLOSE=#")];

	snprintf(buffer, sizeof(buffer), "AT+QICLOSE=%u", id);
    send_at_cmd(buffer, &ictx.sem_response, MDM_CMD_TIMEOUT);
    clean_socket(id);
	return 0;
}

static int ec20_connect(int id, const struct sockaddr *addr, socklen_t addrlen) {
	int ret;
	char type[4], 
         buf[sizeof("AT+QIOPEN=1,##,\"TCP\",###############,#####,#####,#\r")];
	struct ec20_socket *sock;

    sock = (struct ec20_socket *)&ictx.sockets[id];
	if (!sock) {
		LOG_ERR("Can not locate socket id: %u", id);
	}

	int port = ntohs((net_sin(addr)->sin_port));

	if (port < 0) {
		LOG_ERR("Invalid port: %d", port);
		return -EINVAL;
	}

    /*
    if (sock->type == SOCK_STREAM) {
        strcpy(type, SOCK_TYPE_TCP);
    } else {
        strcpy(type, SOCK_TYPE_UDP);
    }
    */
    strcpy(type, SOCK_TYPE_TCP);

    /* send AT commands(AT+QIOPEN=<contextID>,<socket>,"<TCP/UDP>","<IP_address>/<domain_name>", */
    /* <remote_port>,<local_port>,<access_mode>) to connect TCP server */
    /* contextID   = 1 : use same contextID as AT+QICSGP & AT+QIACT */
    /* local_port  = 0 : local port assigned automatically */
    /* access_mode = 0 : Buffer mode */


    snprintk(buf, sizeof(buf), "AT+QIOPEN=1,%d,\"%s\",\"%s\",%d,0,0", 
            id, type, modem_sprint_ip_addr(addr), port);
    ret = send_at_cmd(buf, &ictx.sem_response, MDM_CMD_TIMEOUT);

	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
        goto error;
	}

    /* Wait until ^QIWRITE returns 0,1. */
	ret = k_sem_take(&sock->sem_write_ready, MDM_CMD_CONN_TIMEOUT);
	if (ret < 0) {
		ec20_close(id);
		return ret;
	}

	return 0;

error:
	if (ret == -ETIMEDOUT) {
		return -ETIMEDOUT;
	} else {
		return -EIO;
	}
}

static ssize_t ec20_sendto(int id, const void *buf, size_t len, int flags,
			   const struct sockaddr *to, socklen_t tolen)
{
	return -ENOTSUP;
}

static ssize_t ec20_send(int id, const void *buf, size_t len, int flags)
{
    struct ec20_socket *sock;
	char buf_cmd[sizeof("AT+QISEND=#,####")];
	int ret;

	if (len > MDM_MAX_BUF_LENGTH) {
		return -EMSGSIZE;
	}

	sock = (struct ec20_socket *)&ictx.sockets[id];
	if (!sock) {
		LOG_ERR("Can't locate socket for id: %u", id);
		return -EINVAL;
	}

    ictx.last_socket_id = id;
	snprintf(buf_cmd, sizeof(buf_cmd), "AT+QISEND=%u,%u", id, len);
	ret = send_at_cmd(buf_cmd, &sock->sem_write_ready, MDM_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Write request failed.");
		goto error;
	}

    k_sleep(MDM_PROMPT_CMD_DELAY);

	k_sem_reset(&ictx.sem_response);
	mdm_receiver_send(&ictx.mdm_ctx, buf, len);
	k_sem_take(&ictx.sem_response, MDM_CMD_SEND_TIMEOUT);

	return len;
error:
	if (ret == -ETIMEDOUT) {
		return -ETIMEDOUT;
	} else {
		return -EIO;
	}
}

static ssize_t ec20_recv(int id, void *buf, size_t max_len, int flags) {
    struct ec20_socket *sock = &ictx.sockets[id];
	char buffer_send[sizeof("AT+QIRD=#")];
	int ret;

	if (max_len > MDM_MAX_BUF_LENGTH) {
		return -EMSGSIZE;
	}

    if (!sock->in_use) {
        return 0;
    }

	if (!sock->data_ready) {
		k_sem_take(&sock->sem_read_ready, MDM_CMD_READ_TIMEOUT);
	}
	//sock->data_ready = false;
	k_sem_reset(&sock->sem_read_ready);
	k_sem_reset(&ictx.sem_response);
	sock->is_in_reading = true;
	sock->p_recv_addr = buf;
	sock->recv_max_len = max_len;
    ictx.last_socket_id = id;
	snprintf(buffer_send, sizeof(buffer_send), "AT+QIRD=%d", id);
	ret = send_at_cmd(buffer_send, &sock->sem_read_ready, MDM_CMD_READ_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Read request failed.");
		goto error;
	}

	k_sem_take(&ictx.sem_response, MDM_CMD_READ_TIMEOUT);

	return sock->bytes_read;
error:
	if (ret == -ETIMEDOUT) {
		return -ETIMEDOUT;
	} else {
		return -EIO;
	}
}

static ssize_t ec20_recvfrom(int id, void *buf, short int len,
			     short int flags, struct sockaddr *from,
			     socklen_t *fromlen)
{
	ARG_UNUSED(from);
	ARG_UNUSED(fromlen);

	return ec20_recv(id, buf, len, flags);
}

/* Support for POLLIN only for now. */
int ec20_poll(struct pollfd *fds, int nfds, int timeout)
{
	struct ec20_socket *sock;
	u8_t countFound = 0;
	int ret;

	for (int i = 0; i < nfds; i++) {
		ictx.sockets[fds[i].fd].is_polled = true;
	}
	ret = k_sem_take(&ictx.sem_poll, timeout);
	for (int i = 0; i < nfds; i++) {
		sock = &ictx.sockets[fds[i].fd];
		if (sock->data_ready == true) {
			fds[i].revents = POLLIN;
			countFound++;
		}
	}

	for (int i = 0; i < nfds; i++) {
		ictx.sockets[fds[i].fd].is_polled = false;
	}

	if (ret == -EBUSY) {
		return -1;
	} else {
		return countFound;
	}
}

static int ec20_getaddrinfo(const char *node, const char *service,
				  const struct addrinfo *hints,
				  struct addrinfo **res) 
{
	unsigned long port = 0;
	int socktype = SOCK_STREAM, proto = IPPROTO_TCP;
	struct addrinfo *ai;
	struct sockaddr *ai_addr;
	int16_t ret = 0; 
	uint32_t ipaddr[4];
	char buf[128];

	/* Check args: */
	if (!node) {
		ret = EAI_NONAME;
		goto exit;
	}
	if (service) {
		port = strtol(service, NULL, 10);
		if (port < 1 || port > USHRT_MAX) {
			ret = EAI_SERVICE;
			goto exit;
		}
	}
	if (!res) {
		ret = EAI_NONAME;
		goto exit;
	}

	/* Now, try to resolve host name: */

	snprintf(buf, sizeof(buf), "AT+QIDNSGIP=1,\"%s\"", node);
    send_at_cmd(buf,  &ictx.sem_response, MDM_CMD_CONN_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Could not resolve name: %s, ret: %d",
			    node, ret);
		ret = EAI_NONAME;
		goto exit;
	}

    ret = k_sem_take(&ictx.sem_response, MDM_CMD_TIMEOUT);
    //TODO check ret
    
    ret = inet_pton(AF_INET, ictx.last_dns_addr, &ipaddr[0]);
    ipaddr[0] = htonl(ipaddr[0]);
    //TODO check ret
    
	/* Allocate out res (addrinfo) struct.	Just one. */
	*res = calloc(1, sizeof(struct addrinfo));
	ai = *res;
	if (!ai) {
		ret = EAI_MEMORY;
		goto exit;
	} else {
		/* Now, alloc the embedded sockaddr struct: */
		ai_addr = calloc(1, sizeof(struct sockaddr));
		if (!ai_addr) {
			ret = EAI_MEMORY;
			free(*res);
			goto exit;
		}
	}

	/* Now, fill in the fields of res (addrinfo struct): */
	ai->ai_family = AF_INET;
	if (hints) {
		socktype = hints->ai_socktype;
	}
	ai->ai_socktype = socktype;

	if (socktype == SOCK_DGRAM) {
		proto = IPPROTO_UDP;
	}
	ai->ai_protocol = proto;

	/* Fill sockaddr struct fields based on family: */
	if (ai->ai_family == AF_INET) {
		net_sin(ai_addr)->sin_family = ai->ai_family;
		net_sin(ai_addr)->sin_addr.s_addr = htonl(ipaddr[0]);
		net_sin(ai_addr)->sin_port = htons(port);
		ai->ai_addrlen = sizeof(struct sockaddr_in);
	} else {
        goto exit;
    }
	ai->ai_addr = ai_addr;
    return 0;

exit:
	return ret;
}

static void ec20_freeaddrinfo(struct addrinfo *res)
{
	__ASSERT_NO_MSG(res);

	free(res->ai_addr);
	free(res);
}

static const struct socket_offload ec20_socket_ops = {
	.socket = ec20_socket,
	.close = ec20_close,
	.connect = ec20_connect,
	.send = ec20_send,
	.sendto = ec20_sendto,
	.recv = ec20_recv,
	.recvfrom = ec20_recvfrom,
	.poll = ec20_poll,
    .getaddrinfo = ec20_getaddrinfo,
    .freeaddrinfo = ec20_freeaddrinfo,
};

/*** OFFLOAD FUNCTIONS ***/

static int offload_get(sa_family_t family,
		       enum net_sock_type type,
		       enum net_ip_protocol ip_proto,
		       struct net_context **context)
{
    LOG_ERR("NET_SOCKETS_OFFLOAD must be configured for this driver");
    return -1;
}

static struct net_offload offload_funcs = {
	.get = offload_get,
};

static inline u8_t *modem_get_mac(struct device *dev)
{
	struct modem_iface_ctx *ctx = dev->driver_data;

	ctx->mac_addr[0] = 0x00;
	ctx->mac_addr[1] = 0x10;

	UNALIGNED_PUT(sys_cpu_to_be32(sys_rand32_get()),
		      (u32_t *)(ctx->mac_addr + 2));

	return ctx->mac_addr;
}

static void offload_iface_init(struct net_if *iface)
{
	struct device *dev = net_if_get_device(iface);
	struct modem_iface_ctx *ctx = dev->driver_data;

	iface->if_dev->offload = &offload_funcs;
	net_if_set_link_addr(iface, modem_get_mac(dev),
			     sizeof(ctx->mac_addr),
			     NET_LINK_ETHERNET);
	ctx->iface = iface;
    socket_offload_register(&ec20_socket_ops);
}

static struct net_if_api api_funcs = {
	.init	= offload_iface_init,
};

NET_DEVICE_OFFLOAD_INIT(modem_ec20, "MODEM_EC20",
			modem_init, &ictx,
			NULL, CONFIG_MODEM_EC20_INIT_PRIORITY, &api_funcs,
			MDM_MAX_DATA_LENGTH);
