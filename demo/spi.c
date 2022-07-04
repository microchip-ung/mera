// Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT


#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include "main.h"
#include "trace.h"

typedef struct {
    int fd;
    int freq;
    int padding;
} spi_conf_t;

static spi_conf_t spi_conf;

static mscc_appl_trace_module_t trace_module = {
    .name = "spi"
};

enum {
    TRACE_GROUP_DEFAULT,
    TRACE_GROUP_CNT
};

static mscc_appl_trace_group_t trace_groups[TRACE_GROUP_CNT] = {
    // TRACE_GROUP_DEFAULT
    {
        .name = "default",
        .level = MERA_TRACE_LEVEL_ERROR
    },
};

/* MEBA callouts */
#define TO_SPI(_a_)     (_a_ & 0x007FFFFF) /* 23 bit SPI address */
#define SPI_NR_BYTES     7                 /* Number of bytes to transmit or receive */
#define SPI_PADDING_MAX 15                 /* Maximum number of optional padding bytes */

int spi_reg_read(struct mera_inst *inst,
                 const uintptr_t  addr,
                 uint32_t         *const value)
{
    uint8_t tx[SPI_NR_BYTES + SPI_PADDING_MAX] = { 0 };
    uint8_t rx[sizeof(tx)] = { 0 };
    uint32_t siaddr = TO_SPI(addr);
    spi_conf_t *conf = &spi_conf;
    int spi_padding = conf->padding;
    int ret;

    memset(tx, 0xff, sizeof(tx));
    tx[0] = (uint8_t)(siaddr >> 16);
    tx[1] = (uint8_t)(siaddr >> 8);
    tx[2] = (uint8_t)(siaddr >> 0);

    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long) tx,
        .rx_buf = (unsigned long) rx,
        .len = SPI_NR_BYTES + spi_padding,
        .delay_usecs = 0,
        .speed_hz = conf->freq,
        .bits_per_word = 8,
    };

    ret = ioctl(conf->fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 1) {
        T_E("spi_read: %s", strerror(errno));
        return -1;
    }

    uint32_t rxword =
            (rx[3 + spi_padding] << 24) |
            (rx[4 + spi_padding] << 16) |
            (rx[5 + spi_padding] << 8) |
            (rx[6 + spi_padding] << 0);

    *value = rxword;

    T_D("RX: %02x %02x %02x-%02x %02x %02x %02x",
        tx[0], tx[1], tx[2],
        rx[3 + spi_padding],
        rx[4 + spi_padding],
        rx[5 + spi_padding],
        rx[6 + spi_padding]);

    return 0;
}

int spi_reg_write(struct mera_inst *inst,
                  const uintptr_t  addr,
                  const uint32_t   value)
{
    uint8_t tx[SPI_NR_BYTES] = { 0 };
    uint8_t rx[sizeof(tx)] = { 0 };
    uint32_t siaddr = TO_SPI(addr);
    spi_conf_t *conf = &spi_conf;
    int ret;

    tx[0] = (uint8_t)(0x80 | (siaddr >> 16));
    tx[1] = (uint8_t)(siaddr >> 8);
    tx[2] = (uint8_t)(siaddr >> 0);
    tx[3] = (uint8_t)(value >> 24);
    tx[4] = (uint8_t)(value >> 16);
    tx[5] = (uint8_t)(value >> 8);
    tx[6] = (uint8_t)(value >> 0);

    T_D("TX: %02x %02x %02x-%02x %02x %02x %02x",
        tx[0], tx[1], tx[2], tx[3], tx[4], tx[5], tx[6]);

    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long) tx,
        .rx_buf = (unsigned long) rx,
        .len = sizeof(tx),
        .delay_usecs = 0,
        .speed_hz = conf->freq,
        .bits_per_word = 8,
    };

    ret = ioctl(conf->fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret < 1) {
        T_E("spi_write: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int spi_io_init(const char *device, int freq, int padding)
{
    spi_conf_t *conf = &spi_conf;
    int fd, ret, mode = 0;

    if (padding > SPI_PADDING_MAX) {
        T_E("Invalid spi_padding %d, Range is 0..%d",
            padding, SPI_PADDING_MAX);
        return -1;
    }
    fd = open(device, O_RDWR);
    if (fd < 0) {
        T_E("%s: %s", device, strerror(errno));
        return -1;
    }

    // TODO, delete this once it has been fixed in the DTS
    ret = ioctl(fd, SPI_IOC_WR_MODE, &mode);
    if (ret < 0) {
        T_E("Error setting spi wr-mode");
        close(fd);
        return -1;
    }

    // TODO, delete this once it has been fixed in the DTS
    ret = ioctl(fd, SPI_IOC_RD_MODE, &mode);
    if (ret < 0) {
        T_E("Error setting spi wr-mode");
        close(fd);
        return -1;
    }

    T_D("spi: %s opened", device);
    conf->fd = fd;
    conf->freq = freq;
    conf->padding = padding;

    return 0;
}

void mscc_appl_spi_init(mscc_appl_init_t *init)
{
    if (init->cmd == MSCC_INIT_CMD_REG) {
        mscc_appl_trace_register(&trace_module, trace_groups, TRACE_GROUP_CNT);
    }
}
