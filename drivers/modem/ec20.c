/*
 * Copyright (c) 2019 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(modem_ec20, CONFIG_MODEM_LOG_LEVEL);

#include <kernel.h>
#include <ctype.h>
#include <errno.h>
#include <zephyr.h>
#include <drivers/gpio.h>
#include <device.h>
#include <init.h>

#include <net/net_if.h>
#include <net/net_offload.h>
#include <net/socket_offload.h>
#include <net/socket_offload_ops.h>

#include "modem_context.h"
#include "modem_socket.h"
#include "modem_cmd_handler.h"
#include "modem_iface_uart.h"

#if !defined(CONFIG_MODEM_EC20_MANUAL_MCCMNO)
#define CONFIG_MODEM_EC20_MANUAL_MCCMNO ""
#endif

/* pin settings */
enum mdm_control_pins {
	MDM_POWER = 0,
	MDM_RESET,
	MAX_MDM_CONTROL_PINS,
};

static struct modem_pin modem_pins[] = {
	/* MDM_POWER */
	MODEM_PIN(DT_INST_0_QUECTEL_EC20_MDM_POWER_GPIOS_CONTROLLER,
		  DT_INST_0_QUECTEL_EC20_MDM_POWER_GPIOS_PIN, GPIO_DIR_OUT),

	/* MDM_RESET */
	MODEM_PIN(DT_INST_0_QUECTEL_EC20_MDM_RESET_GPIOS_CONTROLLER,
		  DT_INST_0_QUECTEL_EC20_MDM_RESET_GPIOS_PIN, GPIO_DIR_OUT),
};

#define MDM_UART_DEV_NAME		DT_INST_0_QUECTEL_EC20_BUS_NAME

#define MDM_POWER_ENABLE		1
#define MDM_POWER_DISABLE		0
#define MDM_RESET_NOT_ASSERTED  1
#define MDM_RESET_ASSERTED		0

#define MDM_CMD_TIMEOUT			    K_SECONDS(5)
#define MDM_CLOSE_CMD_TIMEOUT	    K_SECONDS(1)
#define MDM_CMD_READ_TIMEOUT		K_SECONDS(10)
#define MDM_CMD_SEND_TIMEOUT		K_SECONDS(10)
#define MDM_CMD_CONN_TIMEOUT		K_SECONDS(31)
#define MDM_CMD_DNS_TIMEOUT			K_SECONDS(30)

#define MDM_REGISTRATION_TIMEOUT	K_SECONDS(180)
#define MDM_PROMPT_CMD_DELAY		K_MSEC(75)

#define MDM_MAX_BUF_LENGTH		1460
#define MDM_MAX_DATA_LENGTH		1460

#define MDM_RECV_MAX_BUF		30
#define MDM_RECV_BUF_SIZE		255

#define MDM_MAX_SOCKETS			11
#define MDM_BASE_SOCKET_NUM		0

#define MDM_NETWORK_RETRY_COUNT		3
#define MDM_WAIT_FOR_RSSI_COUNT		10
#define MDM_WAIT_FOR_RSSI_DELAY		K_SECONDS(2)

#define BUF_ALLOC_TIMEOUT K_SECONDS(1)

#define MDM_MANUFACTURER_LENGTH		10
#define MDM_MODEL_LENGTH		16
#define MDM_MIN_MODEL_LENGTH	5
#define MDM_REVISION_LENGTH		64
#define MDM_IMEI_LENGTH			16

#define DNS_ADDR_LENGTH			80

#define RSSI_TIMEOUT_SECS		30

#define SOCK_TYPE_TCP           "TCP"

NET_BUF_POOL_DEFINE(mdm_recv_pool, MDM_RECV_MAX_BUF, MDM_RECV_BUF_SIZE,
		    0, NULL);

/* RX thread structures */
K_THREAD_STACK_DEFINE(modem_rx_stack,
		       CONFIG_MODEM_EC20_RX_STACK_SIZE);
struct k_thread modem_rx_thread;

/* RX thread work queue */
K_THREAD_STACK_DEFINE(modem_workq_stack,
		      CONFIG_MODEM_EC20_RX_WORKQ_STACK_SIZE);
static struct k_work_q modem_workq;

/* socket read callback data */
struct socket_read_data {
	char *recv_buf;
	size_t recv_buf_len;
	struct sockaddr *recv_addr;
	u16_t recv_read_len;
};

struct modem_data {
	struct net_if *net_iface;
	u8_t mac_addr[6];

	/* modem interface */
	struct modem_iface_uart_data iface_data;
	u8_t iface_isr_buf[MDM_RECV_BUF_SIZE];
	u8_t iface_rb_buf[MDM_MAX_DATA_LENGTH];

	/* modem cmds */
	struct modem_cmd_handler_data cmd_handler_data;
	u8_t cmd_read_buf[MDM_RECV_BUF_SIZE];
	u8_t cmd_match_buf[MDM_RECV_BUF_SIZE];

	/* socket data */
	struct modem_socket_config socket_config;
	struct modem_socket sockets[MDM_MAX_SOCKETS];

	/* RSSI work */
	struct k_delayed_work rssi_query_work;

	/* modem data */
	char mdm_manufacturer[MDM_MANUFACTURER_LENGTH];
	char mdm_model[MDM_MODEL_LENGTH];
	char mdm_revision[MDM_REVISION_LENGTH];
	char mdm_imei[MDM_IMEI_LENGTH];

	/* modem state */
	int ev_creg;

	/* response semaphore */
	struct k_sem sem_response;

	/* last DNS addr */
    char last_dns_addr[DNS_ADDR_LENGTH];
    
    /* last read socket_id */
    int last_read_sock;
};

static struct modem_data mdata;
static struct modem_context mctx;

/* helper macro to keep readability */
#define ATOI(s_, value_, desc_) modem_atoi(s_, value_, desc_, __func__)

/**
 * @brief  Convert string to long integer, but handle errors
 *
 * @param  s: string with representation of integer number
 * @param  err_value: on error return this value instead
 * @param  desc: name the string being converted
 * @param  func: function where this is called (typically __func__)
 *
 * @retval return integer conversion on success, or err_value on error
 */
static int modem_atoi(const char *s, const int err_value,
		      const char *desc, const char *func)
{
	int ret;
	char *endptr;

	ret = (int)strtol(s, &endptr, 10);
	if (!endptr || *endptr != '\0') {
		LOG_ERR("bad %s '%s' in %s", log_strdup(s), log_strdup(desc),
			log_strdup(func));
		return err_value;
	}

	return ret;
}

/*
 * Modem Response Command Handlers
 */

/* Handler: OK */
MODEM_CMD_DEFINE(on_cmd_ok)
{
	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&mdata.sem_response);
}

/* Handler: ERROR */
MODEM_CMD_DEFINE(on_cmd_error)
{
	modem_cmd_handler_set_error(data, -EIO);
	k_sem_give(&mdata.sem_response);
}

/* Handler: +QIGETERROR: <err>[0] */
MODEM_CMD_DEFINE(on_cmd_exterror)
{
	/* TODO: map extended error codes to values */
	modem_cmd_handler_set_error(data, -EIO);
	k_sem_give(&mdata.sem_response);
}

/*
 * Modem Info Command Handlers
 */

/* Handler: <manufacturer> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_manufacturer)
{
	size_t out_len;

	out_len = net_buf_linearize(mdata.mdm_manufacturer,
				    sizeof(mdata.mdm_manufacturer) - 1,
				    data->rx_buf, 0, len);
	mdata.mdm_manufacturer[out_len] = '\0';
	LOG_INF("Manufacturer: %s", log_strdup(mdata.mdm_manufacturer));
}

/* Handler: <model> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_model)
{
	size_t out_len;

	out_len = net_buf_linearize(mdata.mdm_model,
				    sizeof(mdata.mdm_model) - 1,
				    data->rx_buf, 0, len);
	mdata.mdm_model[out_len] = '\0';
	LOG_INF("Model: %s", log_strdup(mdata.mdm_model));
}

/* Handler: <rev> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_revision)
{
	size_t out_len;

	out_len = net_buf_linearize(mdata.mdm_revision,
				    sizeof(mdata.mdm_revision) - 1,
				    data->rx_buf, 0, len);
	mdata.mdm_revision[out_len] = 0;
	LOG_INF("Revision: %s", log_strdup(mdata.mdm_revision));
}

/* Handler: <IMEI> */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_imei)
{
	size_t out_len;

	out_len = net_buf_linearize(mdata.mdm_imei, sizeof(mdata.mdm_imei) - 1,
				    data->rx_buf, 0, len);
	mdata.mdm_imei[out_len] = '\0';
	LOG_INF("IMEI: %s", log_strdup(mdata.mdm_imei));
}

/* Handler: +CSQ: rssi[0],ber[1] */
MODEM_CMD_DEFINE(on_cmd_atcmdinfo_rssi_csq)
{
	int rssi;

	rssi = ATOI(argv[0], 0, "rssi");
    if (rssi >= 0 && rssi <= 97) {
        mctx.data_rssi = -140 + rssi;
    } else {
        mctx.data_rssi = -1000;
    }

	LOG_INF("RSSI: %d", mctx.data_rssi);
}

/* Handler: +QIOPEN: <socket_id>,0 */
MODEM_CMD_DEFINE(on_cmd_sockcreate)
{
	struct modem_socket *sock;
    int fd = ATOI(argv[0], 0, "socket_id"),
        ret = ATOI(argv[1], 0, "err");

    if (ret != 0) {
        LOG_WRN("Socket not connected");
        modem_cmd_handler_set_error(data, -ENOTCONN);
        return;
    }

    LOG_INF("create socket=%d err=%d", fd, ret);
	sock = modem_socket_from_fd(&mdata.socket_config, fd);
	if (!sock ) {
		LOG_ERR("Can't locate socket from fd:%d", fd);
		return;
	}

    if (ret != 0) {
        modem_socket_put(&mdata.socket_config, sock->sock_fd);
        return;
    }

	k_sem_give(&mdata.sem_response);
}

/* Handler: SEND [OK|FAIL] */
MODEM_CMD_DEFINE(on_cmd_sockwrite)
{
	/* TODO: check length against original send length*/
	k_sem_give(&mdata.sem_response);
}

/* Handler: +QICLOSE: <socket_id> */
/* Handler: +QIURC: "closed",<socket_id> */
MODEM_CMD_DEFINE(on_cmd_socknotifyclose)
{
	struct modem_socket *sock;
	sock = modem_socket_from_id(&mdata.socket_config,
				    ATOI(argv[0], 0, "socket_id"));
	if (!sock) {
		return;
	}

    LOG_WRN("noti close=%d", sock->id);
	modem_socket_put(&mdata.socket_config, sock->sock_fd);
}

/* Handler: +QIURC: "recv",<socket_id> */
MODEM_CMD_DEFINE(on_cmd_socknotifydata)
{
	int socket_id;
	struct modem_socket *sock;

	socket_id = ATOI(argv[0], 0, "socket_id");
    LOG_WRN("noti data=%d", socket_id);
	sock = modem_socket_from_id(&mdata.socket_config, socket_id);
	if (!sock) {
		return;
	}

    k_sem_give(&sock->sem_data_ready);
    if (sock->is_polled) {
        /* unblock poll() */
        k_sem_give(&mdata.socket_config.sem_poll);
    }
}

/* Handler: +QIURC: "dnsgip","<addr>" */
MODEM_CMD_DEFINE(on_cmd_getaddr)
{
	size_t out_len;

	out_len = net_buf_linearize(mdata.last_dns_addr, sizeof(mdata.last_dns_addr) - 1, 
				    data->rx_buf, 0, len);
	mdata.last_dns_addr[out_len - 1] = 0;
	k_sem_give(&mdata.sem_response);
	LOG_INF("Resolve addr: %s", log_strdup(mdata.last_dns_addr));
}

MODEM_CMD_DEFINE(on_cmd_sockdata)
{
	struct modem_socket *sock = NULL;
	struct socket_read_data *sock_data;
    int socket_id = mdata.last_read_sock;

	sock = modem_socket_from_id(&mdata.socket_config, socket_id);
	if (!sock) {
		LOG_ERR("Socket not found! (%d)", socket_id);
		return;
	}

	if (!sock->packet_sizes[0]) {
        return;
    }

	sock_data = (struct socket_read_data *)sock->data;
	if (!sock_data) {
		LOG_ERR("Socket data not found! Skip handling (%d)", socket_id);
		return;
	}

    // hack for read data from cmd_handler
    // EC20 data format:
    // +QIRD: 0,178\r\n<read_data>\r\nOK
    strcat(sock_data->recv_buf, argv[0]);
    strcat(sock_data->recv_buf, "\r\n");

    LOG_WRN("read-%d", strlen(sock_data->recv_buf));
    if (strlen(sock_data->recv_buf) >= sock->packet_sizes[0]) {
		sock_data->recv_read_len = strlen(sock_data->recv_buf);
		/* unblock sockets waiting on recv() */
		k_sem_give(&sock->sem_data_ready);
		if (sock->is_polled) {
			/* unblock poll() */
			k_sem_give(&mdata.socket_config.sem_poll);
		}
	}
}

MODEM_CMD_DEFINE(on_cmd_sockread)
{
    LOG_WRN("QIRD Got %s", log_strdup(argv[0]));

	struct modem_socket *sock = NULL;
	int ret, bytes_read,
        socket_id = mdata.last_read_sock,
        new_total = ATOI(argv[0], 0, "new_total");

    // TODO: check socket_id
	sock = modem_socket_from_id(&mdata.socket_config, socket_id);
	if (!sock) {
		LOG_ERR("Socket not found! (%d)", socket_id);
		return;
	}

    /*
    if (ret < 0 || bytes_read == 0) {
        return;
    }
    */

	ret = modem_socket_packet_size_update(&mdata.socket_config, sock,
					      new_total);
    /*

    out_len = net_buf_linearize(buffer, sizeof(buffer), *buf, 0, len);
    buffer[out_len] = 0;
    bytes_read = atoi(buffer);
    LOG_DBG("Reported %d bytes to be read. len: %d %s", bytes_read, len, log_strdup(buffer));

    while (i < len) {
        i++;
        net_buf_pull_u8(*buf);
    }

    i = 0;
    size_t bytes_skip = 0;
    while (i < bytes_read + 2) {
        if (!(*buf)->len) {
			*buf = net_buf_frag_del(NULL, *buf);
		}

        modem_read_rx(buf);
        if (*buf) {
            out_len = (*buf)->len;
            while (out_len) {
                out_len--;
                c = net_buf_pull_u8(*buf);
                if (bytes_skip < 2) {
                    bytes_skip++;
                    continue;
                } else {
                    sock->p_recv_addr[i] = c;
                }
                i++;
            }
        }
        k_yield();
    }
    sock->p_recv_addr[bytes_read] = 0;

    sock->bytes_read = bytes_read;
    sock->is_in_reading = false;
	k_sem_give(&sock->sem_read_ready);
    */
}

// Handle +CREG: 0,1
MODEM_CMD_DEFINE(on_cmd_socknotifycreg)
{
	mdata.ev_creg = ATOI(argv[0], 0, "stat");
	LOG_DBG("CREG:%d", mdata.ev_creg);
}

MODEM_CMD_DEFINE(on_cmd_socket_error)
{
    /*
	char buffer[10];
	size_t out_len;

	out_len = net_buf_linearize(buffer, sizeof(buffer) - 1, *buf, 0, len);
	buffer[out_len] = 0;
	strtok(buffer, ",");
	strtok(buffer, ",");
	mdata.last_error = -atoi(strtok(buffer, ","));
	LOG_ERR("+CME %d", mdata.last_error);
	k_sem_give(&mdata.sem_response);
    */
}

/* RX thread */
static void modem_rx(void)
{
	while (true) {
		/* wait for incoming data */
		k_sem_take(&mdata.iface_data.rx_sem, K_FOREVER);
		mctx.cmd_handler.process(&mctx.cmd_handler, &mctx.iface);

		/* give up time if we have a solid stream of data */
		k_yield();
	}
}

static int pin_init(void)
{
	LOG_INF("Setting Modem Pins");

	LOG_DBG("MDM_RESET_PIN -> NOT_ASSERTED");
	modem_pin_write(&mctx, MDM_RESET, MDM_RESET_NOT_ASSERTED);

	LOG_DBG("MDM_POWER_PIN -> DISABLE");
	modem_pin_write(&mctx, MDM_POWER, MDM_POWER_DISABLE);
	k_sleep(K_SECONDS(4));

	LOG_DBG("MDM_POWER_PIN -> ENABLE");
	modem_pin_write(&mctx, MDM_POWER, MDM_POWER_ENABLE);
	k_sleep(K_SECONDS(1));

	LOG_DBG("MDM_POWER_PIN -> DISABLE");
	modem_pin_write(&mctx, MDM_POWER, MDM_POWER_DISABLE);
	k_sleep(K_SECONDS(9));

	unsigned int irq_lock_key = irq_lock();

	LOG_DBG("MDM_POWER_PIN -> ENABLE");
	modem_pin_write(&mctx, MDM_POWER, MDM_POWER_ENABLE);
	k_sleep(K_SECONDS(1));

	irq_unlock(irq_lock_key);

	k_sleep(K_SECONDS(10));

	modem_pin_config(&mctx, MDM_POWER, GPIO_DIR_IN);

	LOG_INF("... Done!");

	return 0;
}

static void modem_rssi_query_work(struct k_work *work)
{
	struct modem_cmd cmd = MODEM_CMD("+CSQ: ", on_cmd_atcmdinfo_rssi_csq, 2U, ",");
	static char *send_cmd = "AT+CSQ";
	int ret;

	/* query modem RSSI */
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     &cmd, 1U, send_cmd, &mdata.sem_response,
			     MDM_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("AT+CSQ ret:%d", ret);
	}

	/* re-start RSSI query work */
	if (work) {
		k_delayed_work_submit_to_queue(&modem_workq,
					       &mdata.rssi_query_work,
					       K_SECONDS(RSSI_TIMEOUT_SECS));
	}
}

static void modem_reset(void)
{
	int ret = 0, retry_count = 0, counter = 0;

	static struct setup_cmd setup_cmds[] = {
		/* turn off echo */
		SETUP_CMD_NOHANDLE("ATE0"),
		SETUP_CMD("AT+GMI", "", on_cmd_atcmdinfo_manufacturer, 0U, ""),
		SETUP_CMD("AT+CGMM", "", on_cmd_atcmdinfo_model, 0U, ""),
		SETUP_CMD("AT+CGSN", "", on_cmd_atcmdinfo_imei, 0U, ""),
		SETUP_CMD("AT+GMR", "", on_cmd_atcmdinfo_revision, 0U, ""),
		SETUP_CMD_NOHANDLE("AT+QICFG=\"dataformat\",0,0"),
		SETUP_CMD_NOHANDLE("AT+COPS=0,0"),
    };

	/* bring down network interface */
	atomic_clear_bit(mdata.net_iface->if_dev->flags, NET_IF_UP);

restart:
	/* stop RSSI delay work */
	k_delayed_work_cancel(&mdata.rssi_query_work);

    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
                     NULL, 0, "AT+CFUN=1,1", &mdata.sem_response,
				     MDM_CMD_TIMEOUT);
    // Soft reset first or restart
    if (ret != 0) {
        pin_init();
    } 

	LOG_INF("Waiting for modem to respond");

	/* Give the modem a while to start responding to simple 'AT' commands.
	 * Also wait for CSPS=1 or RRCSTATE=1 notification
	 */
	ret = -1;
	while (counter++ < 50 && ret < 0) {
		k_sleep(K_SECONDS(2));
		ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
				     NULL, 0, "AT", &mdata.sem_response,
				     MDM_CMD_TIMEOUT);
		if (ret < 0 && ret != -ETIMEDOUT) {
			break;
		}
	}

	if (ret < 0) {
		LOG_ERR("MODEM WAIT LOOP ERROR: %d", ret);
		goto error;
	}

	ret = modem_cmd_handler_setup_cmds(&mctx.iface, &mctx.cmd_handler,
					   setup_cmds, ARRAY_SIZE(setup_cmds),
					   &mdata.sem_response,
					   MDM_REGISTRATION_TIMEOUT);

	LOG_INF("Waiting for network");

	/* wait for +CREG: 1 notification (20 seconds max) */
	counter = 0;
	while (counter++ < 20 && mdata.ev_creg != 1) {
		k_sleep(K_SECONDS(1));
	}

	/* query modem RSSI */
	modem_rssi_query_work(NULL);
	k_sleep(MDM_WAIT_FOR_RSSI_DELAY);

	counter = 0;
	/* wait for RSSI < 0 and > -1000 */
	while (counter++ < MDM_WAIT_FOR_RSSI_COUNT &&
	       (mctx.data_rssi >= 0 ||
		mctx.data_rssi <= -1000)) {
		modem_rssi_query_work(NULL);
		k_sleep(MDM_WAIT_FOR_RSSI_DELAY);
	}

	if (mctx.data_rssi >= 0 || mctx.data_rssi <= -1000) {
		retry_count++;
		if (retry_count >= MDM_NETWORK_RETRY_COUNT) {
			LOG_ERR("Failed network init.  Too many attempts!");
			ret = -ENETUNREACH;
			goto error;
		}

		LOG_ERR("Failed network init.  Restarting process.");
		goto restart;
	}

    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
                 NULL, 0, "AT+QIACT=1", &mdata.sem_response,
                 MDM_CMD_TIMEOUT);
    if (ret < 0 && ret != -ETIMEDOUT) {
        goto error;
    }

    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
                 NULL, 0, "AT+QIDNSCFG=1,\"119.29.29.29\",\"8.8.8.8\"", &mdata.sem_response,
                 MDM_CMD_TIMEOUT);
    if (ret < 0 && ret != -ETIMEDOUT) {
        goto error;
    }

	LOG_INF("Network is ready.");

	/* Set iface up */
	net_if_up(mdata.net_iface);

	/* start RSSI query */
	k_delayed_work_submit_to_queue(&modem_workq,
				       &mdata.rssi_query_work,
				       K_SECONDS(RSSI_TIMEOUT_SECS));

error:
	return;
}

static struct modem_cmd response_cmds[] = {
	MODEM_CMD("OK", on_cmd_ok, 0U, ""),
	MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
	MODEM_CMD("+QIGETERROR:", on_cmd_exterror, 1U, ""),
};


/* UNSOLICITED Commands */
static struct modem_cmd unsol_cmds[] = {
	MODEM_CMD("+QICLOSE: ", on_cmd_socknotifyclose, 1U, ""),
	MODEM_CMD("+QIURC: \"closed\",", on_cmd_socknotifyclose, 1U, ""),
	MODEM_CMD("+QIURC: \"recv\",", on_cmd_socknotifydata, 1U, ""),
	MODEM_CMD("+QIOPEN: ", on_cmd_sockcreate, 2U, ","),
	MODEM_CMD("+QIURC: \"dnsgip\",\"", on_cmd_getaddr, 0U, ""),
	MODEM_CMD("+CREG: ", on_cmd_socknotifycreg, 1U, ""),
};

static int modem_init(struct device *dev)
{
	int ret = 0;

	ARG_UNUSED(dev);

	k_sem_init(&mdata.sem_response, 0, 1);

	/* initialize the work queue */
	k_work_q_start(&modem_workq,
		       modem_workq_stack,
		       K_THREAD_STACK_SIZEOF(modem_workq_stack),
		       K_PRIO_COOP(7));

	/* socket config */
	mdata.socket_config.sockets = &mdata.sockets[0];
	mdata.socket_config.sockets_len = ARRAY_SIZE(mdata.sockets);
	mdata.socket_config.base_socket_num = MDM_BASE_SOCKET_NUM;
	ret = modem_socket_init(&mdata.socket_config);
	if (ret < 0) {
		goto error;
	}

	/* cmd handler */
	mdata.cmd_handler_data.cmds[CMD_RESP] = response_cmds;
	mdata.cmd_handler_data.cmds_len[CMD_RESP] = ARRAY_SIZE(response_cmds);
	mdata.cmd_handler_data.cmds[CMD_UNSOL] = unsol_cmds;
	mdata.cmd_handler_data.cmds_len[CMD_UNSOL] = ARRAY_SIZE(unsol_cmds);
	mdata.cmd_handler_data.read_buf = &mdata.cmd_read_buf[0];
	mdata.cmd_handler_data.read_buf_len = sizeof(mdata.cmd_read_buf);
	mdata.cmd_handler_data.match_buf = &mdata.cmd_match_buf[0];
	mdata.cmd_handler_data.match_buf_len = sizeof(mdata.cmd_match_buf);
	mdata.cmd_handler_data.buf_pool = &mdm_recv_pool;
	mdata.cmd_handler_data.alloc_timeout = BUF_ALLOC_TIMEOUT;

	ret = modem_cmd_handler_init(&mctx.cmd_handler,
				     &mdata.cmd_handler_data);
	if (ret < 0) {
		goto error;
	}

	/* modem interface */
	mdata.iface_data.isr_buf = &mdata.iface_isr_buf[0];
	mdata.iface_data.isr_buf_len = sizeof(mdata.iface_isr_buf);
	mdata.iface_data.rx_rb_buf = &mdata.iface_rb_buf[0];
	mdata.iface_data.rx_rb_buf_len = sizeof(mdata.iface_rb_buf);
	ret = modem_iface_uart_init(&mctx.iface, &mdata.iface_data,
				    MDM_UART_DEV_NAME);
	if (ret < 0) {
		goto error;
	}

	/* Set modem data storage */
	mctx.data_manufacturer = mdata.mdm_manufacturer;
	mctx.data_model = mdata.mdm_model;
	mctx.data_revision = mdata.mdm_revision;
	mctx.data_imei = mdata.mdm_imei;

	/* pin setup */
	mctx.pins = modem_pins;
	mctx.pins_len = ARRAY_SIZE(modem_pins);

	mctx.driver_data = &mdata;

	ret = modem_context_register(&mctx);
	if (ret < 0) {
		LOG_ERR("Error registering modem context: %d", ret);
		goto error;
	}

	/* start RX thread */
	k_thread_create(&modem_rx_thread, modem_rx_stack,
			K_THREAD_STACK_SIZEOF(modem_rx_stack),
			(k_thread_entry_t) modem_rx,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);

	/* init RSSI query */
	k_delayed_work_init(&mdata.rssi_query_work, modem_rssi_query_work);

    // TODO: test
	//net_if_up(mdata.net_iface);
    // TODO: PROD
    modem_reset();

error:
	return ret;
}

static int ec20_socket(int family,int type, int proto)
{
	/* defer modem's socket create call to bind() */
	return modem_socket_get(&mdata.socket_config, family, type, proto);
}

static int ec20_close(int sock_fd) {
    LOG_WRN("ec20_close");
	struct modem_socket *sock;
	char buf[sizeof("AT+QICLOSE=##")];
	int ret;

    mdata.last_read_sock = -1;
	sock = modem_socket_from_fd(&mdata.socket_config, sock_fd);
	if (!sock) {
		/* socket was already closed?  Exit quietly here. */
		return 0;
	}

	/* make sure we assigned an id */
	if (sock->id < mdata.socket_config.base_socket_num) {
		return 0;
	}

	snprintk(buf, sizeof(buf), "AT+QICLOSE=%d", sock->id);
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     NULL, 0U, buf,
			     &mdata.sem_response, MDM_CLOSE_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
	}

	modem_socket_put(&mdata.socket_config, sock_fd);
    return 0;
}

static int ec20_connect(int sock_fd, const struct sockaddr *addr, socklen_t addrlen) {
	struct modem_socket *sock;
	int ret;
	char buf[sizeof("AT+QIOPEN=1,##,\"TCP\",###############,#####,#####,#")];
	u16_t dst_port = 0U;

	if (!addr) {
		return -EINVAL;
	}

	sock = modem_socket_from_fd(&mdata.socket_config, sock_fd);
	if (!sock) {
		LOG_ERR("Can't locate socket from fd:%d", sock_fd);
		return -EINVAL;
	}

	if (sock->id < mdata.socket_config.base_socket_num - 1) {
		LOG_ERR("Invalid socket_id(%d) from fd:%d",
			sock->id, sock_fd);
		return -EINVAL;
	}

	/* make sure we've created the socket */
	if (sock->id == mdata.socket_config.sockets_len + 1) {
        sock->id = sock_fd;
	}

	memcpy(&sock->dst, addr, sizeof(*addr));
	if (addr->sa_family == AF_INET6) {
		dst_port = ntohs(net_sin6(addr)->sin6_port);
	} else if (addr->sa_family == AF_INET) {
		dst_port = ntohs(net_sin(addr)->sin_port);
	} else {
        ret = -EPFNOSUPPORT;
        goto exit;
	}

	/* skip socket connect if UDP */
	if (sock->ip_proto == IPPROTO_UDP) {
		return 0;
	}

    /* send AT commands(AT+QIOPEN=<contextID>,<socket>,"<TCP/UDP>","<IP_address>/<domain_name>", */
    /* <remote_port>,<local_port>,<access_mode>) to connect TCP server */
    /* contextID   = 1 : use same contextID as AT+QICSGP & AT+QIACT */
    /* local_port  = 0 : local port assigned automatically */
    /* access_mode = 0 : Buffer mode */
    snprintk(buf, sizeof(buf), "AT+QIOPEN=1,%d,\"TCP\",\"%s\",%d,0,0", 
            sock->id, modem_context_sprint_ip_addr(addr), dst_port);
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     NULL, 0U, buf,
			     &mdata.sem_response, MDM_CMD_TIMEOUT);

	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
	}

	k_sem_reset(&mdata.sem_response);
	ret = k_sem_take(&mdata.sem_response, MDM_CMD_TIMEOUT);

exit:
    return ret;
}

static inline struct net_buf *read_rx_allocator(s32_t timeout, void *user_data) {
	return net_buf_alloc((struct net_buf_pool *)user_data, timeout);
}

/* send binary data */
static int send_socket_data(struct modem_socket *sock,
			    const struct sockaddr *dst_addr,
			    const char *buf, size_t buf_len, int timeout)
{
	int ret;
	char send_buf[sizeof("AT+QISEND=#,#####\r\n")];
	struct modem_cmd cmd[] = {
		MODEM_CMD("SEND OK", on_cmd_sockwrite, 0U, ""),
		MODEM_CMD("SEND FAIL", on_cmd_sockwrite, 0U, ""),
	};

	if (!sock) {
		return -EINVAL;
	}

	k_sem_take(&mdata.cmd_handler_data.sem_tx_lock, K_FOREVER);

    LOG_INF("QISEND ID=%d", sock->id);
    snprintk(send_buf, sizeof(send_buf), "AT+QISEND=%u,%u", sock->id, buf_len);
	ret = modem_cmd_send_nolock(&mctx.iface, &mctx.cmd_handler,
				    NULL, 0U, send_buf, NULL, K_NO_WAIT);

	if (ret < 0) {
		goto exit;
	}

	/* set command handlers */
	ret = modem_cmd_handler_update_cmds(&mdata.cmd_handler_data,
					    cmd, ARRAY_SIZE(cmd), true);
	if (ret < 0) {
		goto exit;
	}

	/* slight pause per spec so that @ prompt is received */
	k_sleep(MDM_PROMPT_CMD_DELAY);
	mctx.iface.write(&mctx.iface, buf, buf_len);

	if (timeout == K_NO_WAIT) {
		ret = 0;
		goto exit;
	}

	k_sem_reset(&mdata.sem_response);
	ret = k_sem_take(&mdata.sem_response, timeout);

	if (ret == 0) {
		ret = modem_cmd_handler_get_error(&mdata.cmd_handler_data);
	} else if (ret == -EAGAIN) {
		ret = -ETIMEDOUT;
	}

exit:
	/* unset handler commands and ignore any errors */
	(void)modem_cmd_handler_update_cmds(&mdata.cmd_handler_data,
					    NULL, 0U, false);
	k_sem_give(&mdata.cmd_handler_data.sem_tx_lock);

	return ret;
}

static ssize_t ec20_sendto(int sock_fd, const void *buf, size_t len, int flags,
			   const struct sockaddr *to, socklen_t tolen)
{
    LOG_INF("ec20_sendto");
	struct modem_socket *sock;

	if (!buf || len == 0) {
		return -EINVAL;
	}

	sock = modem_socket_from_fd(&mdata.socket_config, sock_fd);
	if (!sock) {
		LOG_ERR("Can't locate socket from fd:%d", sock_fd);
		return -EINVAL;
	}

	if (!to && sock->ip_proto == IPPROTO_UDP) {
		to = &sock->dst;
	}

	return send_socket_data(sock, to, buf, len, MDM_CMD_TIMEOUT);
}

static ssize_t ec20_send(int sock_fd, const void *buf, size_t len, int flags)
{
	return ec20_sendto(sock_fd, buf, len, flags, NULL, 0U);
}

static ssize_t ec20_recv(int sock_fd, void *buf, size_t max_len, int flags) {
    LOG_WRN("ec20_recv");
	struct modem_socket *sock;
	int ret;
	struct modem_cmd cmd[] = {
		MODEM_CMD("+QIRD: ", on_cmd_sockread, 1U, ""),
		MODEM_CMD("", on_cmd_sockdata, 1U, ""),
	};
	char sendbuf[sizeof("AT+QIRD=##")];
	struct socket_read_data sock_data;

	if (!buf || max_len == 0) {
		return -EINVAL;
	}

	if (max_len > MDM_MAX_BUF_LENGTH) {
		return -EMSGSIZE;
	}

	sock = modem_socket_from_fd(&mdata.socket_config, sock_fd);
	if (!sock) {
		LOG_ERR("Can't locate socket from fd:%d", sock_fd);
		return -EINVAL;
	}

	if (flags & MSG_PEEK) {
		return -ENOTSUP;
	} else if (flags & MSG_DONTWAIT && !sock->packet_sizes[0]) {
		return 0;
	}

	if (!sock->packet_sizes[0]) {
		k_sem_take(&sock->sem_data_ready, K_FOREVER);
	}

	snprintk(sendbuf, sizeof(sendbuf), "AT+QIRD=%d", sock->id);

	/* socket read settings */
	(void)memset(&sock_data, 0, sizeof(sock_data));
	sock_data.recv_buf = buf;
	sock_data.recv_buf_len = max_len;
	sock->data = &sock_data;

    mdata.last_read_sock = sock->id;
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     cmd, ARRAY_SIZE(cmd), sendbuf, &mdata.sem_response,
			     flags & MSG_DONTWAIT ? K_NO_WAIT :
						    MDM_CMD_TIMEOUT);
	if (ret < 0) {
		goto exit;
	}

	ret = sock_data.recv_read_len;
    mdata.last_read_sock = -1;

exit:
	/* clear socket data */
	sock->data = NULL;
	return ret;
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
    /*
	struct modem_socket *sock;
	u8_t countFound = 0;
	int ret;

	for (int i = 0; i < nfds; i++) {
		mdata.sockets[fds[i].fd].is_polled = true;
	}
	ret = k_sem_take(&mdata.sem_poll, timeout);
	for (int i = 0; i < nfds; i++) {
		sock = &mdata.sockets[fds[i].fd];
		if (sock->data_ready == true) {
			fds[i].revents = POLLIN;
			countFound++;
		}
	}

	for (int i = 0; i < nfds; i++) {
		mdata.sockets[fds[i].fd].is_polled = false;
	}

	if (ret == -EBUSY) {
		return -1;
	} else {
		return countFound;
	}
    */

    return 0;
}

static int ec20_getaddrinfo(const char *node, const char *service,
				  const struct addrinfo *hints,
				  struct addrinfo **res) 
{
	int16_t ret = 0; 
	unsigned long port = 0;
	int socktype = SOCK_STREAM, proto = IPPROTO_TCP;
	struct addrinfo *ai;
	struct sockaddr *ai_addr;
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
    snprintk(buf, sizeof(buf), "AT+QIDNSGIP=1,\"%s\"", node);
	ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler,
			     NULL, 0U, buf,
			     &mdata.sem_response, MDM_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("%s ret:%d", log_strdup(buf), ret);
		ret = EAI_NONAME;
        goto exit;
	}

    /* wait for DNS data */
    k_sem_take(&mdata.sem_response, MDM_CMD_DNS_TIMEOUT);

    ret = inet_pton(AF_INET, mdata.last_dns_addr, &ipaddr[0]);
    ipaddr[0] = htonl(ipaddr[0]);
    
	*res = calloc(1, sizeof(struct addrinfo));
	ai = *res;
	if (!ai) {
		ret = EAI_MEMORY;
		goto exit;
	} else {
		ai_addr = calloc(1, sizeof(struct sockaddr));
		if (!ai_addr) {
			ret = EAI_MEMORY;
			free(*res);
			goto exit;
		}
	}

	ai->ai_family = AF_INET;
	if (hints) {
		socktype = hints->ai_socktype;
	}
	ai->ai_socktype = socktype;

	if (socktype == SOCK_DGRAM) {
		proto = IPPROTO_UDP;
	}
	ai->ai_protocol = proto;

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

static int ec20_bind(int sock_fd, const struct sockaddr *addr,
			socklen_t addrlen)
{
    LOG_INF("ec20_bind");
	struct modem_socket *sock = NULL;

	sock = modem_socket_from_fd(&mdata.socket_config, sock_fd);
	if (!sock) {
		LOG_ERR("Can't locate socket from fd:%d", sock_fd);
		return -EINVAL;
	}

	/* save bind address information */
	memcpy(&sock->src, addr, sizeof(*addr));

	/* make sure we've created the socket */
	if (sock->id == mdata.socket_config.sockets_len + 1) {
		//return create_socket(sock, addr);
	}

	return 0;
}


static const struct socket_offload modem_socket_offload = {
	.socket = ec20_socket,
	.close = ec20_close,
	.bind = ec20_bind,
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

static int net_offload_dummy_get(sa_family_t family,
				 enum net_sock_type type,
				 enum net_ip_protocol ip_proto,
				 struct net_context **context)
{

	LOG_ERR("NET_SOCKET_OFFLOAD must be configured for this driver");

	return -ENOTSUP;
}

/* placeholders, until Zepyr IP stack updated to handle a NULL net_offload */
static struct net_offload modem_net_offload = {
	.get = net_offload_dummy_get,
};

#define HASH_MULTIPLIER		37
static u32_t hash32(char *str, int len)
{
	u32_t h = 0;
	int i;

	for (i = 0; i < len; ++i) {
		h = (h * HASH_MULTIPLIER) + str[i];
	}

	return h;
}

static inline u8_t *modem_get_mac(struct device *dev)
{
	struct modem_data *data = dev->driver_data;
	u32_t hash_value;

	data->mac_addr[0] = 0x00;
	data->mac_addr[1] = 0x10;

	/* use IMEI for mac_addr */
	hash_value = hash32(mdata.mdm_imei, strlen(mdata.mdm_imei));

	UNALIGNED_PUT(hash_value, (u32_t *)(data->mac_addr + 2));

	return data->mac_addr;
}

static void modem_net_iface_init(struct net_if *iface)
{
	struct device *dev = net_if_get_device(iface);
	struct modem_data *data = dev->driver_data;

	/* Direct socket offload used instead of net offload: */
	iface->if_dev->offload = &modem_net_offload;
	net_if_set_link_addr(iface, modem_get_mac(dev),
			     sizeof(data->mac_addr),
			     NET_LINK_ETHERNET);
	socket_offload_register(&modem_socket_offload);
	data->net_iface = iface;
}

static struct net_if_api api_funcs = {
	.init = modem_net_iface_init,
};

NET_DEVICE_OFFLOAD_INIT(modem_ec20, "MODEM_EC20",
			modem_init, &mdata, NULL, 
            CONFIG_MODEM_EC20_INIT_PRIORITY, &api_funcs,
			MDM_MAX_DATA_LENGTH);
