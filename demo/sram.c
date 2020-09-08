// Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
// SPDX-License-Identifier: MIT


#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>

#if (__BYTE_ORDER == __BIG_ENDIAN)
#define HOST_CVT(x) (x)
#else
#define HOST_CVT(x) __builtin_bswap32((x))  /* PCIe is LE, so swap */
#endif

static int trace_enabled = 0;

static void trace_printf(int line, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    vprintf(format, va);
    va_end(va);
    printf("\n");
}

#define T_D(...) { if (trace_enabled)  trace_printf(__LINE__, __VA_ARGS__); }
#define T_E(...) trace_printf(__LINE__, __VA_ARGS__)

static volatile uint32_t *base_mem;

static int reg_check(uint32_t addr)
{
    if (addr >= 0x1ffff) {
        T_E("address range is 17 bits");
        return -1;
    }
    if (addr & 3) {
        T_E("address must be 32-bit word aligned");
        return -1;
    }
    return 0;
}

/* MEBA callouts */
static int reg_read(uint32_t addr, uint32_t *val)
{
    if (reg_check(addr) < 0) {
        return -1;
    }
    *val = HOST_CVT(base_mem[addr / 4]);
    return 0;
}

static int reg_write(uint32_t addr, uint32_t val)
{
    if (reg_check(addr) < 0) {
        return -1;
    }
    base_mem[addr / 4] = HOST_CVT(val);
    return 0;
}

static int uio_init(void)
{
    const char *driver = "mscc_sram";
    const char *top = "/sys/class/uio";
    DIR *dir;
    struct dirent *dent;
    char fn[PATH_MAX], devname[128];
    FILE *fp;
    char iodev[512];
    size_t mapsize;
    int dev_fd, len, rc = -1;

    if (!(dir = opendir(top))) {
        T_E("operdir(%s) failed", top);
        return rc;
    }

    while ((dent = readdir(dir)) != NULL) {
        if (dent->d_name[0] == '.') {
            continue;
        }

        snprintf(fn, sizeof(fn), "%s/%s/name", top, dent->d_name);
        fp = fopen(fn, "r");
        if (!fp) {
            T_E("UIO: Failed to open: %s", fn);
            continue;
        }

        const char *rrd = fgets(devname, sizeof(devname), fp);
        fclose(fp);

        if (!rrd) {
            T_E("UIO: Failed to read: %s", fn);
            continue;
        }

        len = strlen(devname);
        if (len > 0 && devname[len - 1] == '\n') {
            devname[len - 1] = '\0';
        }
        T_D("UIO: %s -> %s", fn, devname);
        if (!strstr(devname, driver)) {
            continue;
        }

        snprintf(iodev, sizeof(iodev), "/dev/%s", dent->d_name);
        snprintf(fn, sizeof(fn), "%s/%s/maps/map0/size", top, dent->d_name);
        fp = fopen(fn, "r");
        if (!fp) {
            continue;
        }

        if (fscanf(fp, "%zi", &mapsize)) {
            fclose(fp);
            rc = 0;
            T_D("Using UIO device: %s", devname);
            break;
        }
        fclose(fp);
    }
    closedir(dir);

    if (rc < 0) {
        T_E("No suitable UIO device found!");
        return rc;
    }

    /* Open the UIO device file */
    T_D("Using UIO, found '%s' driver at %s, size: %zu", driver, iodev, mapsize);
    dev_fd = open(iodev, O_RDWR);
    if (dev_fd < 1) {
        T_E("open(%s) failed", iodev);
        rc = -1;
    } else {
        /* mmap the UIO device */
        base_mem = mmap(NULL, mapsize, PROT_READ|PROT_WRITE, MAP_SHARED, dev_fd, 0);
        if (base_mem != MAP_FAILED) {
            T_D("Mapped register memory @ %p", base_mem);
        } else {
            T_E("mmap failed");
            rc = -1;
        }
    }
    return rc;
}

int to_uint32_t(const char *c, uint32_t *val)
{
    unsigned long int v = 0;
    char *ep;

    v = strtoul(c, &ep, 0);
    if (*c == 0 || *ep != 0) {
        return -1;
    }
    *val = v;
    return 0;
}

int main(int ac, char *const av[])
{
    const char *cmd;
    int error = 0;
    uint32_t addr, val, len, i, n;
    
    if (uio_init() < 0) {
        return -1;
    }

    cmd = av[1];
    if (ac < 3 || to_uint32_t(av[2], &addr) != 0) {
        error = 1;
    } else if (strcmp(cmd, "read") == 0 && ac == 3) {
        if (reg_read(addr, &val) == 0) {
            printf("read addr: 0x%06x value: 0x%08x\n", addr, val);
        }
    } else if (strcmp(cmd, "write") == 0 && ac == 4) {
        if (to_uint32_t(av[3], &val) != 0) {
            error = 1;
        } else if (reg_write(addr, val) == 0) {
            printf("write addr: 0x%06x value: 0x%08x\n", addr, val);
        }
     } else if (strcmp(cmd, "dump") == 0 && ac == 4) {
        if (to_uint32_t(av[3], &len) != 0) {
            error = 1;
        } else {
            addr &= 0xfffffff0;
            printf("dump: addr: 0x%06x length: 0x%08x\n", addr, len);
            for (i = 0; i < len; i += 4, addr += 4) {
                n = (i & 0xf);
                if (n == 0) {
                    printf("    %06x: ", addr);
                }
                if (reg_read(addr, &val) != 0) {
                    break;
                }
                printf("%08x%s", val, n == 12 ? "\n" : " ");
            }
        }
    } else if (strcmp(cmd, "fill") == 0 && ac == 5) {
        if (to_uint32_t(av[3], &len) != 0 ||
            to_uint32_t(av[4], &val) != 0) {
            error = 1;
        } else {
            printf("fill addr: 0x%06x length: 0x%x value: 0x%08x\n", addr, len, val);
            for (i = 0; i < len; i += 4) {
                if (reg_write(addr + i, val) != 0) {
                    break;
                }
            }
        }
    } else {
        error = 1;
    }
    
    if (error) {
        printf("Usage:\n\n");
        printf("mera-sram-rw read  <addr>\n");
        printf("mera-sram-rw write <addr> <value>\n");
        printf("mera-sram-rw dump  <addr> <length>\n");
        printf("mera-sram-rw fill  <addr> <length> <value>\n");
        return -1;
    }
    return 0;
}
