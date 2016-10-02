/*
 * Copyright (c) 2004-2009 Hyperic, Inc.
 * Copyright (c) 2009 SpringSource, Inc.
 * Copyright (c) 2009-2010 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sigar.h"
#include "sigar_private.h"
#include "sigar_util.h"
#include "sigar_os.h"

#include <sys/param.h>
#include <sys/mount.h>
#if !(defined(__FreeBSD__) && (__FreeBSD_version >= 800000))
#include <nfs/rpcv2.h>
#endif
#include <nfs/nfsproto.h>

#include <sys/dkstat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/vmmeter.h>
#include <fcntl.h>
#include <stdio.h>

#if defined(__FreeBSD__) && (__FreeBSD_version >= 500013)
#define SIGAR_FREEBSD5_NFSSTAT
#include <nfsclient/nfs.h>
#include <nfsserver/nfs.h>
#else
#include <nfs/nfs.h>
#endif

#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <dirent.h>
#include <errno.h>

#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>

#define NMIB(mib) (sizeof(mib)/sizeof(mib[0]))

#ifdef __FreeBSD__
#  if (__FreeBSD_version >= 500013)
#    define SIGAR_FREEBSD5
#  else
#    define SIGAR_FREEBSD4
#  endif
#endif

#if defined(SIGAR_FREEBSD5)

#define KI_FD   ki_fd
#define KI_PID  ki_pid
#define KI_PPID ki_ppid
#define KI_PRI  ki_pri.pri_user
#define KI_NICE ki_nice
#define KI_COMM ki_comm
#define KI_STAT ki_stat
#define KI_UID  ki_ruid
#define KI_GID  ki_rgid
#define KI_EUID ki_svuid
#define KI_EGID ki_svgid
#define KI_SIZE ki_size
#define KI_RSS  ki_rssize
#define KI_TSZ  ki_tsize
#define KI_DSZ  ki_dsize
#define KI_SSZ  ki_ssize
#define KI_FLAG ki_flag
#define KI_START ki_start

#elif defined(SIGAR_FREEBSD4)

#define KI_FD   kp_proc.p_fd
#define KI_PID  kp_proc.p_pid
#define KI_PPID kp_eproc.e_ppid
#define KI_PRI  kp_proc.p_priority
#define KI_NICE kp_proc.p_nice
#define KI_COMM kp_proc.p_comm
#define KI_STAT kp_proc.p_stat
#define KI_UID  kp_eproc.e_pcred.p_ruid
#define KI_GID  kp_eproc.e_pcred.p_rgid
#define KI_EUID kp_eproc.e_pcred.p_svuid
#define KI_EGID kp_eproc.e_pcred.p_svgid
#define KI_SIZE XXX
#define KI_RSS  kp_eproc.e_vm.vm_rssize
#define KI_TSZ  kp_eproc.e_vm.vm_tsize
#define KI_DSZ  kp_eproc.e_vm.vm_dsize
#define KI_SSZ  kp_eproc.e_vm.vm_ssize
#define KI_FLAG kp_eproc.e_flag
#define KI_START kp_proc.p_starttime

#endif

#define PROCFS_STATUS(status) \
    ((((status) != SIGAR_OK) && !sigar->proc_mounted) ? \
     SIGAR_ENOTIMPL : status)

static int get_koffsets(sigar_t *sigar)
{
    int i;
    struct nlist klist[] = {
        { "_cp_time" },
        { "_cnt" },
        { NULL }
    };

    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    kvm_nlist(sigar->kmem, klist);

    for (i=0; i<KOFFSET_MAX; i++) {
        sigar->koffsets[i] = klist[i].n_value;
    }

    return SIGAR_OK;
}

static int kread(sigar_t *sigar, void *data, int size, long offset)
{
    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    if (kvm_read(sigar->kmem, offset, data, size) != size) {
        return errno;
    }

    return SIGAR_OK;
}

int sigar_sys_info_get_uuid(sigar_t *sigar, char uuid[SIGAR_SYS_INFO_LEN])
{
    return SIGAR_ENOTIMPL;
}

int sigar_os_open(sigar_t **sigar)
{
    int mib[2];
    int ncpu;
    size_t len;
    struct timeval boottime;
    struct stat sb;

    len = sizeof(ncpu);
    mib[0] = CTL_HW;
    mib[1] = HW_NCPU;
    if (sysctl(mib, NMIB(mib), &ncpu,  &len, NULL, 0) < 0) {
        return errno;
    }

    len = sizeof(boottime);
    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;
    if (sysctl(mib, NMIB(mib), &boottime, &len, NULL, 0) < 0) {
        return errno;
    }

    *sigar = malloc(sizeof(**sigar));

    (*sigar)->kmem = kvm_open(NULL, NULL, NULL, O_RDONLY, NULL);
    if (stat("/proc/curproc", &sb) < 0) {
        (*sigar)->proc_mounted = 0;
    }
    else {
        (*sigar)->proc_mounted = 1;
    }

    get_koffsets(*sigar);

    (*sigar)->ncpu = ncpu;
    (*sigar)->lcpu = -1;
    (*sigar)->argmax = 0;
    (*sigar)->boot_time = boottime.tv_sec; /* XXX seems off a bit */

    (*sigar)->pagesize = getpagesize();
    (*sigar)->ticks = 100; /* sysconf(_SC_CLK_TCK) == 128 !? */
    (*sigar)->last_pid = -1;

    (*sigar)->pinfo = NULL;

    return SIGAR_OK;
}

int sigar_os_close(sigar_t *sigar)
{
    if (sigar->pinfo) {
        free(sigar->pinfo);
    }
    if (sigar->kmem) {
        kvm_close(sigar->kmem);
    }
    free(sigar);
    return SIGAR_OK;
}

char *sigar_os_error_string(sigar_t *sigar, int err)
{
    switch (err) {
      case SIGAR_EPERM_KMEM:
        return "Failed to open /dev/kmem for reading";
      case SIGAR_EPROC_NOENT:
        return "/proc filesystem is not mounted";
      default:
        return NULL;
    }
}

/* ARG_MAX in FreeBSD 6.0 == 262144, which blows up the stack */
#define SIGAR_ARG_MAX 65536

static int sigar_vmstat(sigar_t *sigar, struct vmmeter *vmstat)
{
    int status;
    size_t size = sizeof(unsigned int);

    status = kread(sigar, vmstat, sizeof(*vmstat),
                   sigar->koffsets[KOFFSET_VMMETER]);

    if (status == SIGAR_OK) {
        return SIGAR_OK;
    }

    SIGAR_ZERO(vmstat);

    /* derived from src/usr.bin/vmstat/vmstat.c */
    /* only collect the ones we actually use */
#define GET_VM_STATS(cat, name, used) \
    if (used) sysctlbyname("vm.stats." #cat "." #name, &vmstat->name, &size, NULL, 0)

    /* sys */
    GET_VM_STATS(sys, v_swtch, 0);
    GET_VM_STATS(sys, v_trap, 0);
    GET_VM_STATS(sys, v_syscall, 0);
    GET_VM_STATS(sys, v_intr, 0);
    GET_VM_STATS(sys, v_soft, 0);

    /* vm */
    GET_VM_STATS(vm, v_vm_faults, 0);
    GET_VM_STATS(vm, v_cow_faults, 0);
    GET_VM_STATS(vm, v_cow_optim, 0);
    GET_VM_STATS(vm, v_zfod, 0);
    GET_VM_STATS(vm, v_ozfod, 0);
    GET_VM_STATS(vm, v_swapin, 1);
    GET_VM_STATS(vm, v_swapout, 1);
    GET_VM_STATS(vm, v_swappgsin, 0);
    GET_VM_STATS(vm, v_swappgsout, 0);
    GET_VM_STATS(vm, v_vnodein, 1);
    GET_VM_STATS(vm, v_vnodeout, 1);
    GET_VM_STATS(vm, v_vnodepgsin, 0);
    GET_VM_STATS(vm, v_vnodepgsout, 0);
    GET_VM_STATS(vm, v_intrans, 0);
    GET_VM_STATS(vm, v_reactivated, 0);
    GET_VM_STATS(vm, v_pdwakeups, 0);
    GET_VM_STATS(vm, v_pdpages, 0);
    GET_VM_STATS(vm, v_dfree, 0);
    GET_VM_STATS(vm, v_pfree, 0);
    GET_VM_STATS(vm, v_tfree, 0);
    GET_VM_STATS(vm, v_page_size, 0);
    GET_VM_STATS(vm, v_page_count, 0);
    GET_VM_STATS(vm, v_free_reserved, 0);
    GET_VM_STATS(vm, v_free_target, 0);
    GET_VM_STATS(vm, v_free_min, 0);
    GET_VM_STATS(vm, v_free_count, 1);
    GET_VM_STATS(vm, v_wire_count, 0);
    GET_VM_STATS(vm, v_active_count, 0);
    GET_VM_STATS(vm, v_inactive_target, 0);
    GET_VM_STATS(vm, v_inactive_count, 1);
    GET_VM_STATS(vm, v_cache_count, 1);
#if (__FreeBSD_version < 1100079 )
     GET_VM_STATS(vm, v_cache_min, 0);
     GET_VM_STATS(vm, v_cache_max, 0);
#endif
    GET_VM_STATS(vm, v_pageout_free_min, 0);
    GET_VM_STATS(vm, v_interrupt_free_min, 0);
    GET_VM_STATS(vm, v_forks, 0);
    GET_VM_STATS(vm, v_vforks, 0);
    GET_VM_STATS(vm, v_rforks, 0);
    GET_VM_STATS(vm, v_kthreads, 0);
    GET_VM_STATS(vm, v_forkpages, 0);
    GET_VM_STATS(vm, v_vforkpages, 0);
    GET_VM_STATS(vm, v_rforkpages, 0);
    GET_VM_STATS(vm, v_kthreadpages, 0);
#undef GET_VM_STATS

    return SIGAR_OK;
}

int sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem)
{
    sigar_uint64_t kern = 0;
    unsigned long mem_total;
    struct vmmeter vmstat;
    int mib[2];
    size_t len;
    int status;

    mib[0] = CTL_HW;

    mib[1] = HW_PAGESIZE;
    len = sizeof(sigar->pagesize);
    if (sysctl(mib, NMIB(mib), &sigar->pagesize, &len, NULL, 0) < 0) {
        return errno;
    }

    mib[1] = HW_PHYSMEM;
    len = sizeof(mem_total);
    if (sysctl(mib, NMIB(mib), &mem_total, &len, NULL, 0) < 0) {
        return errno;
    }

    mem->total = mem_total;

    if ((status = sigar_vmstat(sigar, &vmstat)) == SIGAR_OK) {
        kern = vmstat.v_cache_count + vmstat.v_inactive_count;
        kern *= sigar->pagesize;
        mem->free = vmstat.v_free_count;
        mem->free *= sigar->pagesize;
    }

    mem->used = mem->total - mem->free;

    mem->actual_free = mem->free + kern;
    mem->actual_used = mem->used - kern;

    sigar_mem_calc_ram(sigar, mem);

    return SIGAR_OK;
}

#define SWI_MAXMIB 3

#ifdef SIGAR_FREEBSD5
/* code in this function is based on FreeBSD 5.3 kvm_getswapinfo.c */
static int getswapinfo_sysctl(struct kvm_swap *swap_ary,
                              int swap_max)
{
    int ti, ttl;
    size_t mibi, len, size;
    int soid[SWI_MAXMIB];
    struct xswdev xsd;
    struct kvm_swap tot;
    int unswdev, dmmax;

    /* XXX this can be optimized by using os_open */
    size = sizeof(dmmax);
    if (sysctlbyname("vm.dmmax", &dmmax, &size, NULL, 0) == -1) {
        return errno;
    }

    mibi = SWI_MAXMIB - 1;
    if (sysctlnametomib("vm.swap_info", soid, &mibi) == -1) {
        return errno;
    }

    bzero(&tot, sizeof(tot));
    for (unswdev = 0;; unswdev++) {
        soid[mibi] = unswdev;
        len = sizeof(xsd);
        if (sysctl(soid, mibi + 1, &xsd, &len, NULL, 0) == -1) {
            if (errno == ENOENT) {
                break;
            }
            return errno;
        }
#if 0
        if (len != sizeof(xsd)) {
            _kvm_err(kd, kd->program, "struct xswdev has unexpected "
                     "size;  kernel and libkvm out of sync?");
            return -1;
        }
        if (xsd.xsw_version != XSWDEV_VERSION) {
            _kvm_err(kd, kd->program, "struct xswdev version "
                     "mismatch; kernel and libkvm out of sync?");
            return -1;
        }
#endif
        ttl = xsd.xsw_nblks - dmmax;
        if (unswdev < swap_max - 1) {
            bzero(&swap_ary[unswdev], sizeof(swap_ary[unswdev]));
            swap_ary[unswdev].ksw_total = ttl;
            swap_ary[unswdev].ksw_used = xsd.xsw_used;
            swap_ary[unswdev].ksw_flags = xsd.xsw_flags;
        }
        tot.ksw_total += ttl;
        tot.ksw_used += xsd.xsw_used;
    }

    ti = unswdev;
    if (ti >= swap_max) {
        ti = swap_max - 1;
    }
    if (ti >= 0) {
        swap_ary[ti] = tot;
    }

    return SIGAR_OK;
}
#else
#define getswapinfo_sysctl(swap_ary, swap_max) SIGAR_ENOTIMPL
#endif

#define SIGAR_FS_BLOCKS_TO_BYTES(val, bsize) ((val * bsize) >> 1)

int sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap)
{
    int status;
    struct kvm_swap kswap[1];
    struct vmmeter vmstat;

    if (getswapinfo_sysctl(kswap, 1) != SIGAR_OK) {
        if (!sigar->kmem) {
            return SIGAR_EPERM_KMEM;
        }

        if (kvm_getswapinfo(sigar->kmem, kswap, 1, 0) < 0) {
            return errno;
        }
    }

    if (kswap[0].ksw_total == 0) {
        swap->total = 0;
        swap->used  = 0;
        swap->free  = 0;
        return SIGAR_OK;
    }

    swap->total = kswap[0].ksw_total * sigar->pagesize;
    swap->used  = kswap[0].ksw_used * sigar->pagesize;
    swap->free  = swap->total - swap->used;

    if ((status = sigar_vmstat(sigar, &vmstat)) == SIGAR_OK) {
        swap->page_in = vmstat.v_swapin + vmstat.v_vnodein;
        swap->page_out = vmstat.v_swapout + vmstat.v_vnodeout;
    }
    else {
        swap->page_in = swap->page_out = -1;
    }

    return SIGAR_OK;
}

#ifndef KERN_CPTIME
#define KERN_CPTIME KERN_CP_TIME
#endif

typedef unsigned long cp_time_t;

int sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    int status;
    cp_time_t cp_time[CPUSTATES];
    size_t size = sizeof(cp_time);

    /* try sysctl first, does not require /dev/kmem perms */
    if (sysctlbyname("kern.cp_time", &cp_time, &size, NULL, 0) == -1) {
        status = kread(sigar, &cp_time, sizeof(cp_time),
                       sigar->koffsets[KOFFSET_CPUINFO]);
    }
    else {
        status = SIGAR_OK;
    }

    if (status != SIGAR_OK) {
        return status;
    }

    cpu->user = SIGAR_TICK2MSEC(cp_time[CP_USER]);
    cpu->nice = SIGAR_TICK2MSEC(cp_time[CP_NICE]);
    cpu->sys  = SIGAR_TICK2MSEC(cp_time[CP_SYS]);
    cpu->idle = SIGAR_TICK2MSEC(cp_time[CP_IDLE]);
    cpu->wait = 0; /*N/A*/
    cpu->irq = SIGAR_TICK2MSEC(cp_time[CP_INTR]);
    cpu->soft_irq = 0; /*N/A*/
    cpu->stolen = 0; /*N/A*/
    cpu->total = cpu->user + cpu->nice + cpu->sys + cpu->idle + cpu->irq;

    return SIGAR_OK;
}

#if defined(__FreeBSD__) && (__FreeBSD_version >= 700000)
#define HAVE_KERN_CP_TIMES /* kern.cp_times came later than 7.0, not sure exactly when */
static int sigar_cp_times_get(sigar_t *sigar, sigar_cpu_list_t *cpulist)
{
    int maxcpu, status;
    size_t len = sizeof(maxcpu), size;
    long *times;

    if (sysctlbyname("kern.smp.maxcpus", &maxcpu, &len, NULL, 0) == -1) {
        return errno;
    }

    size = sizeof(long) * maxcpu * CPUSTATES;
    times = malloc(size);
    if (sysctlbyname("kern.cp_times", times, &size, NULL, 0) == -1) {
        status = errno;
    }
    else {
        int i, maxid = (size / CPUSTATES / sizeof(long));
        long *cp_time = times;
        status = SIGAR_OK;

        for (i=0; i<maxid; i++) {
            sigar_cpu_t *cpu;

            SIGAR_CPU_LIST_GROW(cpulist);

            cpu = &cpulist->data[cpulist->number++];
            cpu->user = SIGAR_TICK2MSEC(cp_time[CP_USER]);
            cpu->nice = SIGAR_TICK2MSEC(cp_time[CP_NICE]);
            cpu->sys  = SIGAR_TICK2MSEC(cp_time[CP_SYS]);
            cpu->idle = SIGAR_TICK2MSEC(cp_time[CP_IDLE]);
            cpu->wait = 0; /*N/A*/
            cpu->irq = SIGAR_TICK2MSEC(cp_time[CP_INTR]);
            cpu->soft_irq = 0; /*N/A*/
            cpu->stolen = 0; /*N/A*/
            cpu->total = cpu->user + cpu->nice + cpu->sys + cpu->idle + cpu->irq;
            cp_time += CPUSTATES;
        }
    }

    free(times);
    return status;
}
#endif

int sigar_cpu_list_get(sigar_t *sigar, sigar_cpu_list_t *cpulist)
{
    int status, i;
    sigar_cpu_t *cpu;

    sigar_cpu_list_create(cpulist);

#ifdef HAVE_KERN_CP_TIMES
    if ((status = sigar_cp_times_get(sigar, cpulist)) == SIGAR_OK) {
        return SIGAR_OK;
    }
#endif
    /* XXX no multi cpu in freebsd < 7.0, howbout others?
     * for now just report all metrics on the 1st cpu
     * 0's for the rest
     */
    cpu = &cpulist->data[cpulist->number++];

    status = sigar_cpu_get(sigar, cpu);
    if (status != SIGAR_OK) {
        return status;
    }

    for (i=1; i<sigar->ncpu; i++) {
        SIGAR_CPU_LIST_GROW(cpulist);

        cpu = &cpulist->data[cpulist->number++];
        SIGAR_ZERO(cpu);
    }

    return SIGAR_OK;
}

int sigar_uptime_get(sigar_t *sigar,
                     sigar_uptime_t *uptime)
{
    uptime->uptime   = time(NULL) - sigar->boot_time;

    return SIGAR_OK;
}

int sigar_loadavg_get(sigar_t *sigar,
                      sigar_loadavg_t *loadavg)
{
	loadavg->processor_queue = SIGAR_FIELD_NOTIMPL;
	getloadavg(loadavg->loadavg, 3);

	return SIGAR_OK;
}

int sigar_system_stats_get (sigar_t *sigar,
                            sigar_system_stats_t *system_stats)
{
	return SIGAR_ENOTIMPL;
}

static int proc_fd_get_count(sigar_t *sigar, sigar_pid_t pid, int *num)
{
	sigar_proc_fd_t procfd;
	if (sigar_proc_fd_get(sigar, pid, &procfd) == SIGAR_OK) {
		*num = procfd.total;
	} else {
		return SIGAR_ENOTIMPL;
	}
	return SIGAR_OK;
}

#ifndef KERN_PROC_PROC
/* freebsd 4.x */
#define KERN_PROC_PROC KERN_PROC_ALL
#endif

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist)
{
#if defined(SIGAR_FREEBSD5)
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0 };
    int i, num;
    size_t len;
    struct kinfo_proc *proc;

    if (sysctl(mib, NMIB(mib), NULL, &len, NULL, 0) < 0) {
        return errno;
    }

    proc = malloc(len);

    if (sysctl(mib, NMIB(mib), proc, &len, NULL, 0) < 0) {
        free(proc);
        return errno;
    }

    num = len/sizeof(*proc);

    for (i=0; i<num; i++) {
        if (proc[i].KI_FLAG & P_SYSTEM) {
            continue;
        }
        if (proc[i].KI_PID == 0) {
            continue;
        }
        SIGAR_PROC_LIST_GROW(proclist);
        proclist->data[proclist->number++] = proc[i].KI_PID;
    }

    free(proc);

    return SIGAR_OK;
#else
    int i, num;
    struct kinfo_proc *proc;

    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    proc = kvm_getprocs(sigar->kmem, KERN_PROC_PROC, 0, &num);

    for (i=0; i<num; i++) {
        if (proc[i].KI_FLAG & P_SYSTEM) {
            continue;
        }
        SIGAR_PROC_LIST_GROW(proclist);
        proclist->data[proclist->number++] = proc[i].KI_PID;
    }
#endif

    return SIGAR_OK;
}

static int sigar_get_pinfo(sigar_t *sigar, sigar_pid_t pid)
{
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    size_t len = sizeof(*sigar->pinfo);
    time_t timenow = time(NULL);
    mib[3] = pid;

    if (sigar->pinfo == NULL) {
        sigar->pinfo = malloc(len);
    }

    if (sigar->last_pid == pid) {
        if ((timenow - sigar->last_getprocs) < SIGAR_LAST_PROC_EXPIRE) {
            return SIGAR_OK;
        }
    }

    sigar->last_pid = pid;
    sigar->last_getprocs = timenow;

    if (sysctl(mib, NMIB(mib), sigar->pinfo, &len, NULL, 0) < 0) {
        return errno;
    }

    return SIGAR_OK;
}

#if defined(SHARED_TEXT_REGION_SIZE) && defined(SHARED_DATA_REGION_SIZE)
#  define GLOBAL_SHARED_SIZE (SHARED_TEXT_REGION_SIZE + SHARED_DATA_REGION_SIZE) /* 10.4 SDK */
#endif

int sigar_proc_mem_get(sigar_t *sigar, sigar_pid_t pid,
                       sigar_proc_mem_t *procmem)
{
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    procmem->size =
        (pinfo->KI_TSZ + pinfo->KI_DSZ + pinfo->KI_SSZ) * sigar->pagesize;

    procmem->resident = pinfo->KI_RSS * sigar->pagesize;

    procmem->share = SIGAR_FIELD_NOTIMPL;

    procmem->page_faults  = SIGAR_FIELD_NOTIMPL;
    procmem->minor_faults = SIGAR_FIELD_NOTIMPL;
    procmem->major_faults = SIGAR_FIELD_NOTIMPL;
    return SIGAR_OK;
}

int sigar_proc_cumulative_disk_io_get(sigar_t *sigar, sigar_pid_t pid,
                           sigar_proc_cumulative_disk_io_t *proc_cumulative_disk_io)
{
    return SIGAR_ENOTIMPL;
}


int sigar_proc_cred_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_cred_t *proccred)
{
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

#if defined(__OpenBSD__) || defined(__NetBSD__)
    proccred->uid  = pinfo->p_ruid;
    proccred->gid  = pinfo->p_rgid;
    proccred->euid = pinfo->p_uid;
    proccred->egid = pinfo->p_gid;
#else
    proccred->uid  = pinfo->KI_UID;
    proccred->gid  = pinfo->KI_GID;
    proccred->euid = pinfo->KI_EUID;
    proccred->egid = pinfo->KI_EGID;
#endif

    return SIGAR_OK;
}

#define tv2msec(tv) \
   (((sigar_uint64_t)tv.tv_sec * SIGAR_MSEC) + (((sigar_uint64_t)tv.tv_usec) / 1000))

int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_time_t *proctime)
{
#ifdef SIGAR_FREEBSD4
    struct user user;
#endif
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

#if defined(SIGAR_FREEBSD5)
    proctime->user  = tv2msec(pinfo->ki_rusage.ru_utime);
    proctime->sys   = tv2msec(pinfo->ki_rusage.ru_stime);
    proctime->total = proctime->user + proctime->sys;
    proctime->start_time = tv2msec(pinfo->KI_START);
#elif defined(SIGAR_FREEBSD4)
    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    status = kread(sigar, &user, sizeof(user),
                   (u_long)pinfo->kp_proc.p_addr);
    if (status != SIGAR_OK) {
        return status;
    }

    proctime->user  = tv2msec(user.u_stats.p_ru.ru_utime);
    proctime->sys   = tv2msec(user.u_stats.p_ru.ru_stime);
    proctime->total = proctime->user + proctime->sys;
    proctime->start_time = tv2msec(user.u_stats.p_start);
#endif

    return SIGAR_OK;
}

int sigar_proc_state_get(sigar_t *sigar, sigar_pid_t pid,
                         sigar_proc_state_t *procstate)
{
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;
    int state = pinfo->KI_STAT;

    if (status != SIGAR_OK) {
        return status;
    }

	procstate->open_files = SIGAR_FIELD_NOTIMPL;

    SIGAR_SSTRCPY(procstate->name, pinfo->KI_COMM);
    procstate->ppid     = pinfo->KI_PPID;
    procstate->priority = pinfo->KI_PRI;
    procstate->nice     = pinfo->KI_NICE;
    procstate->tty      = SIGAR_FIELD_NOTIMPL; /*XXX*/
    procstate->threads  = SIGAR_FIELD_NOTIMPL;
    procstate->processor = SIGAR_FIELD_NOTIMPL;

	int num = 0;
	status = proc_fd_get_count(sigar, pid, &num);
	if (status == SIGAR_OK) {
		procstate->open_files = num;
	}

    switch (state) {
      case SIDL:
        procstate->state = 'D';
        break;
      case SRUN:
#ifdef SONPROC
      case SONPROC:
#endif
        procstate->state = 'R';
        break;
      case SSLEEP:
        procstate->state = 'S';
        break;
      case SSTOP:
        procstate->state = 'T';
        break;
      case SZOMB:
        procstate->state = 'Z';
        break;
      default:
        procstate->state = '?';
        break;
    }

    return SIGAR_OK;
}

int sigar_os_proc_args_get(sigar_t *sigar, sigar_pid_t pid,
                           sigar_proc_args_t *procargs)
{
    char buffer[SIGAR_ARG_MAX+1], *ptr=buffer;
    size_t len = sizeof(buffer);
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_ARGS, 0 };
    mib[3] = pid;

    if (sysctl(mib, NMIB(mib), buffer, &len, NULL, 0) < 0) {
        return errno;
    }

    if (len == 0) {
        procargs->number = 0;
        return SIGAR_OK;
    }

    buffer[len] = '\0';

    while (len > 0) {
        int alen = strlen(ptr)+1;
        char *arg = malloc(alen);

        SIGAR_PROC_ARGS_GROW(procargs);
        memcpy(arg, ptr, alen);

        procargs->data[procargs->number++] = arg;

        len -= alen;
        if (len > 0) {
            ptr += alen;
        }
    }

    return SIGAR_OK;
}

int sigar_proc_env_get(sigar_t *sigar, sigar_pid_t pid,
                       sigar_proc_env_t *procenv)
{
    char **env;
    struct kinfo_proc *pinfo;
    int num;

    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    pinfo = kvm_getprocs(sigar->kmem, KERN_PROC_PID, pid, &num);
    if (!pinfo || (num < 1)) {
        return errno;
    }

    if (!(env = kvm_getenvv(sigar->kmem, pinfo, 9086))) {
        return errno;
    }

    while (*env) {
        char *ptr = *env++;
        char *val = strchr(ptr, '=');
        int klen, vlen, status;
        char key[128]; /* XXX is there a max key size? */

        if (val == NULL) {
            /* not key=val format */
            procenv->env_getter(procenv->data, ptr, strlen(ptr), NULL, 0);
            break;
        }

        klen = val - ptr;
        SIGAR_SSTRCPY(key, ptr);
        key[klen] = '\0';
        ++val;

        vlen = strlen(val);
        status = procenv->env_getter(procenv->data,
                                     key, klen, val, vlen);

        if (status != SIGAR_OK) {
            /* not an error; just stop iterating */
            break;
        }

        ptr += (klen + 1 + vlen + 1);
    }

    return SIGAR_OK;
}

int sigar_proc_fd_get(sigar_t *sigar, sigar_pid_t pid,
                      sigar_proc_fd_t *procfd)
{
    int status;
    bsd_pinfo_t *pinfo;
    struct filedesc filed;
    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    if ((status = sigar_get_pinfo(sigar, pid)) != SIGAR_OK) {
        return status;
    }
    pinfo = sigar->pinfo;

    status = kread(sigar, &filed, sizeof(filed), (u_long)pinfo->KI_FD);
    if (status != SIGAR_OK) {
        return status;
    }
    /* seems the same as the above */
    procfd->total = filed.fd_lastfile;

    return SIGAR_OK;
}

int sigar_proc_exe_get(sigar_t *sigar, sigar_pid_t pid,
                       sigar_proc_exe_t *procexe)
{
    memset(procexe, 0, sizeof(*procexe));

    int len;
    char name[1024];

    (void)SIGAR_PROC_FILENAME(name, pid, "/file");
    if ((len = readlink(name, procexe->name,
                        sizeof(procexe->name)-1)) >= 0) {
        procexe->name[len] = '\0';
    }

	procexe->arch = sigar_elf_file_guess_arch(sigar, procexe->name);

    return SIGAR_OK;
}

int sigar_proc_modules_get(sigar_t *sigar, sigar_pid_t pid,
                           sigar_proc_modules_t *procmods)
{
#if defined(SIGAR_HAS_DLINFO_MODULES)
    if (pid == sigar_pid_get(sigar)) {
        return sigar_dlinfo_modules(sigar, procmods);
    }
#endif
    return SIGAR_ENOTIMPL;
}

#define SIGAR_MICROSEC2NANO(s) \
    ((sigar_uint64_t)(s) * (sigar_uint64_t)1000)

#define TIME_NSEC(t) \
    (SIGAR_SEC2NANO((t).tv_sec) + SIGAR_MICROSEC2NANO((t).tv_usec))

int sigar_thread_cpu_get(sigar_t *sigar,
                         sigar_uint64_t id,
                         sigar_thread_cpu_t *cpu)
{
    /* XXX this is not per-thread, it is for the whole-process.
     * just want to use for the shell time command at the moment.
     */
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);

    cpu->user  = TIME_NSEC(usage.ru_utime);
    cpu->sys   = TIME_NSEC(usage.ru_stime);
    cpu->total = TIME_NSEC(usage.ru_utime) + TIME_NSEC(usage.ru_stime);

    return SIGAR_OK;
}

int sigar_os_fs_type_get(sigar_file_system_t *fsp)
{
    char *type = fsp->sys_type_name;

    /* see sys/disklabel.h */
    switch (*type) {
      case 'f':
        if (strEQ(type, "ffs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
      case 'h':
        if (strEQ(type, "hfs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
      case 'u':
        if (strEQ(type, "ufs")) {
            fsp->type = SIGAR_FSTYPE_LOCAL_DISK;
        }
        break;
    }

    return fsp->type;
}

static void get_fs_options(char *opts, int osize, long flags)
{
    *opts = '\0';
    if (flags & MNT_RDONLY)         strncat(opts, "ro", osize);
    else                            strncat(opts, "rw", osize);
    if (flags & MNT_SYNCHRONOUS)    strncat(opts, ",sync", osize);
    if (flags & MNT_NOEXEC)         strncat(opts, ",noexec", osize);
    if (flags & MNT_NOSUID)         strncat(opts, ",nosuid", osize);
#ifdef MNT_NODEV
    if (flags & MNT_NODEV)          strncat(opts, ",nodev", osize);
#endif
#ifdef MNT_UNION
    if (flags & MNT_UNION)          strncat(opts, ",union", osize);
#endif
    if (flags & MNT_ASYNC)          strncat(opts, ",async", osize);
#ifdef MNT_NOATIME
    if (flags & MNT_NOATIME)        strncat(opts, ",noatime", osize);
#endif
#ifdef MNT_NOCLUSTERR
    if (flags & MNT_NOCLUSTERR)     strncat(opts, ",noclusterr", osize);
#endif
#ifdef MNT_NOCLUSTERW
    if (flags & MNT_NOCLUSTERW)     strncat(opts, ",noclusterw", osize);
#endif
#ifdef MNT_NOSYMFOLLOW
    if (flags & MNT_NOSYMFOLLOW)    strncat(opts, ",nosymfollow", osize);
#endif
#ifdef MNT_SUIDDIR
    if (flags & MNT_SUIDDIR)        strncat(opts, ",suiddir", osize);
#endif
#ifdef MNT_SOFTDEP
    if (flags & MNT_SOFTDEP)        strncat(opts, ",soft-updates", osize);
#endif
    if (flags & MNT_LOCAL)          strncat(opts, ",local", osize);
    if (flags & MNT_QUOTA)          strncat(opts, ",quota", osize);
    if (flags & MNT_ROOTFS)         strncat(opts, ",rootfs", osize);
#ifdef MNT_USER
    if (flags & MNT_USER)           strncat(opts, ",user", osize);
#endif
#ifdef MNT_IGNORE
    if (flags & MNT_IGNORE)         strncat(opts, ",ignore", osize);
#endif
    if (flags & MNT_EXPORTED)       strncat(opts, ",nfs", osize);
}

#ifdef __NetBSD__
#define sigar_statfs statvfs
#define sigar_getfsstat getvfsstat
#define sigar_f_flags f_flag
#else
#define sigar_statfs statfs
#define sigar_getfsstat getfsstat
#define sigar_f_flags f_flags
#endif

int sigar_file_system_list_get(sigar_t *sigar,
                               sigar_file_system_list_t *fslist)
{
    struct sigar_statfs *fs;
    int num, i;
    int is_debug = SIGAR_LOG_IS_DEBUG(sigar);
    long len;

    if ((num = sigar_getfsstat(NULL, 0, MNT_NOWAIT)) < 0) {
        return errno;
    }

    len = sizeof(*fs) * num;
    fs = malloc(len);

    if ((num = sigar_getfsstat(fs, len, MNT_NOWAIT)) < 0) {
        free(fs);
        return errno;
    }

    sigar_file_system_list_create(fslist);

    for (i=0; i<num; i++) {
        sigar_file_system_t *fsp;

#ifdef MNT_AUTOMOUNTED
        if (fs[i].sigar_f_flags & MNT_AUTOMOUNTED) {
            if (is_debug) {
                sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                                 "[file_system_list] skipping automounted %s: %s",
                                 fs[i].f_fstypename, fs[i].f_mntonname);
            }
            continue;
        }
#endif

#ifdef MNT_RDONLY
        if (fs[i].sigar_f_flags & MNT_RDONLY) {
            /* e.g. ftp mount or .dmg image */
            if (is_debug) {
                sigar_log_printf(sigar, SIGAR_LOG_DEBUG,
                                 "[file_system_list] skipping readonly %s: %s",
                                 fs[i].f_fstypename, fs[i].f_mntonname);
            }
            continue;
        }
#endif

        SIGAR_FILE_SYSTEM_LIST_GROW(fslist);

        fsp = &fslist->data[fslist->number++];

        SIGAR_SSTRCPY(fsp->dir_name, fs[i].f_mntonname);
        SIGAR_SSTRCPY(fsp->dev_name, fs[i].f_mntfromname);
        SIGAR_SSTRCPY(fsp->sys_type_name, fs[i].f_fstypename);
        get_fs_options(fsp->options, sizeof(fsp->options)-1, fs[i].sigar_f_flags);

        sigar_fs_type_init(fsp);
    }

    free(fs);
    return SIGAR_OK;
}

int sigar_disk_usage_get(sigar_t *sigar, const char *name,
                         sigar_disk_usage_t *disk)
{
    /* XXX incomplete */
    struct sigar_statfs buf;

    if (sigar_statfs(name, &buf) < 0) {
        return errno;
    }

    SIGAR_DISK_STATS_INIT(disk);

    disk->reads  = buf.f_syncreads + buf.f_asyncreads;
    disk->writes = buf.f_syncwrites + buf.f_asyncwrites;
    return SIGAR_OK;
}

int sigar_file_system_usage_get(sigar_t *sigar,
                                const char *dirname,
                                sigar_file_system_usage_t *fsusage)
{
    int status = sigar_statvfs(sigar, dirname, fsusage);

    if (status != SIGAR_OK) {
        return status;
    }

    fsusage->use_percent = sigar_file_system_usage_calc_used(sigar, fsusage);

    sigar_disk_usage_get(sigar, dirname, &fsusage->disk);

    return SIGAR_OK;
}

/* XXX FreeBSD 5.x+ only? */
#define CTL_HW_FREQ "machdep.tsc_freq"

int sigar_cpu_info_list_get(sigar_t *sigar,
                            sigar_cpu_info_list_t *cpu_infos)
{
    int i;
    unsigned int mhz, mhz_min, mhz_max;
    int cache_size=SIGAR_FIELD_NOTIMPL;
    size_t size;
    char model[128], vendor[128], *ptr;

    size = sizeof(mhz);

    (void)sigar_cpu_core_count(sigar);

    if (sysctlbyname(CTL_HW_FREQ, &mhz, &size, NULL, 0) < 0) {
        mhz = SIGAR_FIELD_NOTIMPL;
    }
    /* TODO */
    mhz_max = SIGAR_FIELD_NOTIMPL;
    mhz_min = SIGAR_FIELD_NOTIMPL;

    if (mhz != SIGAR_FIELD_NOTIMPL) {
        mhz /= 1000000;
    }
    if (mhz_max != SIGAR_FIELD_NOTIMPL) {
        mhz_max /= 1000000;
    }
    if (mhz_min != SIGAR_FIELD_NOTIMPL) {
        mhz_min /= 1000000;
    }

    size = sizeof(model);
    if (sysctlbyname("hw.model", &model, &size, NULL, 0) < 0) {
        int mib[] = { CTL_HW, HW_MODEL };
        size = sizeof(model);
        if (sysctl(mib, NMIB(mib), &model[0], &size, NULL, 0) < 0) {
            strcpy(model, "Unknown");
        }
    }

    if (mhz == SIGAR_FIELD_NOTIMPL) {
        /* freebsd4 */
        mhz = sigar_cpu_mhz_from_model(model);
    }
    /* XXX not sure */
    if (mhz_max == SIGAR_FIELD_NOTIMPL) {
        mhz_max = 0;
    }
    if (mhz_min == SIGAR_FIELD_NOTIMPL) {
        mhz_min = 0;
    }

    if ((ptr = strchr(model, ' '))) {
        if (strstr(model, "Intel")) {
            SIGAR_SSTRCPY(vendor, "Intel");
        }
        else if (strstr(model, "AMD")) {
            SIGAR_SSTRCPY(vendor, "AMD");
        }
        else {
            SIGAR_SSTRCPY(vendor, "Unknown");
        }
        SIGAR_SSTRCPY(model, ptr+1);
    }

    sigar_cpu_info_list_create(cpu_infos);

    for (i=0; i<sigar->ncpu; i++) {
        sigar_cpu_info_t *info;

        SIGAR_CPU_INFO_LIST_GROW(cpu_infos);

        info = &cpu_infos->data[cpu_infos->number++];

        SIGAR_SSTRCPY(info->vendor, vendor);
        SIGAR_SSTRCPY(info->model, model);
        sigar_cpu_model_adjust(sigar, info);

        info->mhz = mhz;
        info->mhz_max = mhz_max;
        info->mhz_min = mhz_min;
        info->cache_size = cache_size;
        info->total_cores = sigar->ncpu;
        info->cores_per_socket = sigar->lcpu;
        info->total_sockets = sigar_cpu_socket_count(sigar);
    }

    return SIGAR_OK;
}

#define rt_s_addr(sa) ((struct sockaddr_in *)(sa))->sin_addr.s_addr

#ifndef SA_SIZE
#define SA_SIZE(sa)                                             \
    (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?      \
        sizeof(long)            :                               \
        1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#endif

int sigar_net_route_list_get(sigar_t *sigar,
                             sigar_net_route_list_t *routelist)
{
    size_t needed;
    int bit;
    char *buf, *next, *lim;
    struct rt_msghdr *rtm;
    int mib[6] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0 };

    if (sysctl(mib, NMIB(mib), NULL, &needed, NULL, 0) < 0) {
        return errno;
    }
#if __FreeBSD_version >= 800000
    if (needed == 0) {
        return SIGAR_ENOTIMPL; /*XXX hoping this is an 8.0beta bug*/
    }
#endif
    buf = malloc(needed);

    if (sysctl(mib, NMIB(mib), buf, &needed, NULL, 0) < 0) {
        free(buf);
        return errno;
    }

    sigar_net_route_list_create(routelist);

    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {
        struct sockaddr *sa;
        sigar_net_route_t *route;
        rtm = (struct rt_msghdr *)next;

        if (rtm->rtm_type != RTM_GET) {
            continue;
        }

        sa = (struct sockaddr *)(rtm + 1);

        if (sa->sa_family != AF_INET) {
            continue;
        }

        SIGAR_NET_ROUTE_LIST_GROW(routelist);
        route = &routelist->data[routelist->number++];
        SIGAR_ZERO(route);

        route->flags = rtm->rtm_flags;
        if_indextoname(rtm->rtm_index, route->ifname);

        for (bit=RTA_DST;
             bit && ((char *)sa < lim);
             bit <<= 1)
        {
            if ((rtm->rtm_addrs & bit) == 0) {
                continue;
            }
            switch (bit) {
              case RTA_DST:
                sigar_net_address_set(route->destination,
                                      rt_s_addr(sa));
                break;
              case RTA_GATEWAY:
                if (sa->sa_family == AF_INET) {
                    sigar_net_address_set(route->gateway,
                                          rt_s_addr(sa));
                }
                break;
              case RTA_NETMASK:
                sigar_net_address_set(route->mask,
                                      rt_s_addr(sa));
                break;
              case RTA_IFA:
                break;
            }

            sa = (struct sockaddr *)((char *)sa + SA_SIZE(sa));
        }
    }

    free(buf);

    return SIGAR_OK;
}

typedef enum {
    IFMSG_ITER_LIST,
    IFMSG_ITER_GET
} ifmsg_iter_e;

typedef struct {
    const char *name;
    ifmsg_iter_e type;
    union {
        sigar_net_interface_list_t *iflist;
        struct if_msghdr *ifm;
    } data;
} ifmsg_iter_t;

static int sigar_ifmsg_init(sigar_t *sigar)
{
    int mib[] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_IFLIST, 0 };
    size_t len;

    if (sysctl(mib, NMIB(mib), NULL, &len, NULL, 0) < 0) {
        return errno;
    }

    if (sigar->ifconf_len < len) {
        sigar->ifconf_buf = realloc(sigar->ifconf_buf, len);
        sigar->ifconf_len = len;
    }

    if (sysctl(mib, NMIB(mib), sigar->ifconf_buf, &len, NULL, 0) < 0) {
        return errno;
    }

    return SIGAR_OK;
}

/**
 * @param name name of the interface
 * @param name_len length of name (w/o \0)
 */
static int has_ifaddr(char *name, size_t name_len)
{
    int sock, status;
    struct ifreq ifr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return errno;
    }
    strncpy(ifr.ifr_name, name, MIN(sizeof(ifr.ifr_name) - 1, name_len));
    ifr.ifr_name[MIN(sizeof(ifr.ifr_name) - 1, name_len)] = '\0';
    if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
        status = SIGAR_OK;
    }
    else {
        status = errno;
    }

    close(sock);
    return status;
}

static int sigar_ifmsg_iter(sigar_t *sigar, ifmsg_iter_t *iter)
{
    char *end = sigar->ifconf_buf + sigar->ifconf_len;
    char *ptr = sigar->ifconf_buf;

    if (iter->type == IFMSG_ITER_LIST) {
        sigar_net_interface_list_create(iter->data.iflist);
    }

    while (ptr < end) {
        char *name;
        struct sockaddr_dl *sdl;
        struct if_msghdr *ifm = (struct if_msghdr *)ptr;

        if (ifm->ifm_type != RTM_IFINFO) {
            break;
        }

        ptr += ifm->ifm_msglen;

        while (ptr < end) {
            struct if_msghdr *next = (struct if_msghdr *)ptr;

            if (next->ifm_type != RTM_NEWADDR) {
                break;
            }

            ptr += next->ifm_msglen;
        }

        sdl = (struct sockaddr_dl *)(ifm + 1);
        if (sdl->sdl_family != AF_LINK) {
            continue;
        }

        switch (iter->type) {
          case IFMSG_ITER_LIST:
            if (sdl->sdl_type == IFT_OTHER) {
                if (has_ifaddr(sdl->sdl_data, sdl->sdl_nlen) != SIGAR_OK) {
                    break;
                }
            }
            else if (!((sdl->sdl_type == IFT_ETHER) ||
                       (sdl->sdl_type == IFT_LOOP)))
            {
                break; /* XXX deal w/ other weirdo interfaces */
            }

            SIGAR_NET_IFLIST_GROW(iter->data.iflist);

            /* sdl_data doesn't include a trailing \0, it is only sdl_nlen long */
            name = malloc(sdl->sdl_nlen+1);
            memcpy(name, sdl->sdl_data, sdl->sdl_nlen);
            name[sdl->sdl_nlen] = '\0'; /* add the missing \0 */

            iter->data.iflist->data[iter->data.iflist->number++] = name;
            break;

          case IFMSG_ITER_GET:
            if (strlen(iter->name) == sdl->sdl_nlen && 0 == memcmp(iter->name, sdl->sdl_data, sdl->sdl_nlen)) {
                iter->data.ifm = ifm;
                return SIGAR_OK;
            }
        }
    }

    switch (iter->type) {
      case IFMSG_ITER_LIST:
        return SIGAR_OK;

      case IFMSG_ITER_GET:
      default:
        return ENXIO;
    }
}

int sigar_net_interface_list_get(sigar_t *sigar,
                                 sigar_net_interface_list_t *iflist)
{
    int status;
    ifmsg_iter_t iter;

    if ((status = sigar_ifmsg_init(sigar)) != SIGAR_OK) {
        return status;
    }

    iter.type = IFMSG_ITER_LIST;
    iter.data.iflist = iflist;

    return sigar_ifmsg_iter(sigar, &iter);
}

#include <ifaddrs.h>

/* in6_prefixlen derived from freebsd/sbin/ifconfig/af_inet6.c */
static int sigar_in6_prefixlen(struct sockaddr *netmask)
{
    struct in6_addr *addr = SIGAR_SIN6_ADDR(netmask);
    u_char *name = (u_char *)addr;
    int size = sizeof(*addr);
    int byte, bit, plen = 0;

    for (byte = 0; byte < size; byte++, plen += 8) {
        if (name[byte] != 0xff) {
            break;
        }
    }
    if (byte == size) {
        return plen;
    }
    for (bit = 7; bit != 0; bit--, plen++) {
        if (!(name[byte] & (1 << bit))) {
            break;
        }
    }
    for (; bit != 0; bit--) {
        if (name[byte] & (1 << bit)) {
            return 0;
        }
    }
    byte++;
    for (; byte < size; byte++) {
        if (name[byte]) {
            return 0;
        }
    }
    return plen;
}

int sigar_net_interface_ipv6_config_get(sigar_t *sigar, const char *name,
                                        sigar_net_interface_config_t *ifconfig)
{
    int status = SIGAR_ENOENT;
    struct ifaddrs *addrs, *ifa;

    if (getifaddrs(&addrs) != 0) {
        return errno;
    }

    for (ifa=addrs; ifa; ifa=ifa->ifa_next) {
        if (ifa->ifa_addr &&
            (ifa->ifa_addr->sa_family == AF_INET6) &&
            strEQ(ifa->ifa_name, name))
        {
            status = SIGAR_OK;
            break;
        }
    }

    if (status == SIGAR_OK) {
        struct in6_addr *addr = SIGAR_SIN6_ADDR(ifa->ifa_addr);

        sigar_net_address6_set(ifconfig->address6, addr);
        sigar_net_interface_scope6_set(ifconfig, addr);
        ifconfig->prefix6_length = sigar_in6_prefixlen(ifa->ifa_netmask);
    }

    freeifaddrs(addrs);

    return status;
}

int sigar_net_interface_config_get(sigar_t *sigar, const char *name,
                                   sigar_net_interface_config_t *ifconfig)
{
    int sock;
    int status;
    ifmsg_iter_t iter;
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;
    struct ifreq ifr;

    if (!name) {
        return sigar_net_interface_config_primary_get(sigar, ifconfig);
    }

    if (sigar->ifconf_len == 0) {
        if ((status = sigar_ifmsg_init(sigar)) != SIGAR_OK) {
            return status;
        }
    }

    SIGAR_ZERO(ifconfig);

    iter.type = IFMSG_ITER_GET;
    iter.name = name;

    if ((status = sigar_ifmsg_iter(sigar, &iter)) != SIGAR_OK) {
        return status;
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return errno;
    }

    ifm = iter.data.ifm;

    SIGAR_SSTRCPY(ifconfig->name, name);

    sdl = (struct sockaddr_dl *)(ifm + 1);

    sigar_net_address_mac_set(ifconfig->hwaddr,
                              LLADDR(sdl),
                              sdl->sdl_alen);

    ifconfig->flags = ifm->ifm_flags;
    ifconfig->mtu = ifm->ifm_data.ifi_mtu;
    ifconfig->metric = ifm->ifm_data.ifi_metric;

    SIGAR_SSTRCPY(ifr.ifr_name, name);

#define ifr_s_addr(ifr) \
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr

    if (!ioctl(sock, SIOCGIFADDR, &ifr)) {
        sigar_net_address_set(ifconfig->address,
                              ifr_s_addr(ifr));
    }

    if (!ioctl(sock, SIOCGIFNETMASK, &ifr)) {
        sigar_net_address_set(ifconfig->netmask,
                              ifr_s_addr(ifr));
    }

    if (ifconfig->flags & IFF_LOOPBACK) {
        sigar_net_address_set(ifconfig->destination,
                              ifconfig->address.addr.in);
        sigar_net_address_set(ifconfig->broadcast, 0);
        SIGAR_SSTRCPY(ifconfig->type,
                      SIGAR_NIC_LOOPBACK);
    }
    else {
        if (!ioctl(sock, SIOCGIFDSTADDR, &ifr)) {
            sigar_net_address_set(ifconfig->destination,
                                  ifr_s_addr(ifr));
        }

        if (!ioctl(sock, SIOCGIFBRDADDR, &ifr)) {
            sigar_net_address_set(ifconfig->broadcast,
                                  ifr_s_addr(ifr));
        }
        SIGAR_SSTRCPY(ifconfig->type,
                      SIGAR_NIC_ETHERNET);
    }

    close(sock);

    /* XXX can we get a better description like win32? */
    SIGAR_SSTRCPY(ifconfig->description,
                  ifconfig->name);

    sigar_net_interface_ipv6_config_init(ifconfig);
    sigar_net_interface_ipv6_config_get(sigar, name, ifconfig);

    return SIGAR_OK;
}

int sigar_net_interface_stat_get(sigar_t *sigar, const char *name,
                                 sigar_net_interface_stat_t *ifstat)
{
    int status;
    ifmsg_iter_t iter;
    struct if_msghdr *ifm;

    if ((status = sigar_ifmsg_init(sigar)) != SIGAR_OK) {
        return status;
    }

    iter.type = IFMSG_ITER_GET;
    iter.name = name;

    if ((status = sigar_ifmsg_iter(sigar, &iter)) != SIGAR_OK) {
        return status;
    }

    ifm = iter.data.ifm;

    ifstat->rx_bytes      = ifm->ifm_data.ifi_ibytes;
    ifstat->rx_packets    = ifm->ifm_data.ifi_ipackets;
    ifstat->rx_errors     = ifm->ifm_data.ifi_ierrors;
    ifstat->rx_dropped    = ifm->ifm_data.ifi_iqdrops;
    ifstat->rx_overruns   = SIGAR_FIELD_NOTIMPL;
    ifstat->rx_frame      = SIGAR_FIELD_NOTIMPL;

    ifstat->tx_bytes      = ifm->ifm_data.ifi_obytes;
    ifstat->tx_packets    = ifm->ifm_data.ifi_opackets;
    ifstat->tx_errors     = ifm->ifm_data.ifi_oerrors;
    ifstat->tx_collisions = ifm->ifm_data.ifi_collisions;
    ifstat->tx_dropped    = SIGAR_FIELD_NOTIMPL;
    ifstat->tx_overruns   = SIGAR_FIELD_NOTIMPL;
    ifstat->tx_carrier    = SIGAR_FIELD_NOTIMPL;

    ifstat->speed         = ifm->ifm_data.ifi_baudrate;

    return SIGAR_OK;
}

static int net_connection_state_get(int state)
{
    switch (state) {
      case TCPS_CLOSED:
        return SIGAR_TCP_CLOSE;
      case TCPS_LISTEN:
        return SIGAR_TCP_LISTEN;
      case TCPS_SYN_SENT:
        return SIGAR_TCP_SYN_SENT;
      case TCPS_SYN_RECEIVED:
        return SIGAR_TCP_SYN_RECV;
      case TCPS_ESTABLISHED:
        return SIGAR_TCP_ESTABLISHED;
      case TCPS_CLOSE_WAIT:
        return SIGAR_TCP_CLOSE_WAIT;
      case TCPS_FIN_WAIT_1:
        return SIGAR_TCP_FIN_WAIT1;
      case TCPS_CLOSING:
        return SIGAR_TCP_CLOSING;
      case TCPS_LAST_ACK:
        return SIGAR_TCP_LAST_ACK;
      case TCPS_FIN_WAIT_2:
        return SIGAR_TCP_FIN_WAIT2;
      case TCPS_TIME_WAIT:
        return SIGAR_TCP_TIME_WAIT;
      default:
        return SIGAR_TCP_UNKNOWN;
    }
}

#if defined(__OpenBSD__) || defined(__NetBSD__)
static int net_connection_get(sigar_net_connection_walker_t *walker, int proto)
{
    int status;
    int istcp = 0, type;
    int flags = walker->flags;
    struct inpcbtable table;
    struct inpcb *head, *next, *prev;
    sigar_t *sigar = walker->sigar;
    u_long offset;

    switch (proto) {
      case IPPROTO_TCP:
        offset = sigar->koffsets[KOFFSET_TCBTABLE];
        istcp = 1;
        type = SIGAR_NETCONN_TCP;
        break;
      case IPPROTO_UDP:
      default:
        return SIGAR_ENOTIMPL;
    }


    status = kread(sigar, &table, sizeof(table), offset);

    if (status != SIGAR_OK) {
        return status;
    }

    prev = head =
        (struct inpcb *)&CIRCLEQ_FIRST(&((struct inpcbtable *)offset)->inpt_queue);

    next = (struct inpcb *)CIRCLEQ_FIRST(&table.inpt_queue);

    while (next != head) {
        struct inpcb inpcb;
        struct tcpcb tcpcb;
        struct socket socket;

        status = kread(sigar, &inpcb, sizeof(inpcb), (long)next);
        prev = next;
        next = (struct inpcb *)CIRCLEQ_NEXT(&inpcb, inp_queue);

        kread(sigar, &socket, sizeof(socket), (u_long)inpcb.inp_socket);

        if ((((flags & SIGAR_NETCONN_SERVER) && socket.so_qlimit) ||
            ((flags & SIGAR_NETCONN_CLIENT) && !socket.so_qlimit)))
        {
            sigar_net_connection_t conn;

            SIGAR_ZERO(&conn);

            if (istcp) {
                kread(sigar, &tcpcb, sizeof(tcpcb), (u_long)inpcb.inp_ppcb);
            }

#ifdef __NetBSD__
            if (inpcb.inp_af == AF_INET6) {
                /*XXX*/
                continue;
            }
#else
            if (inpcb.inp_flags & INP_IPV6) {
                sigar_net_address6_set(conn.local_address,
                                       &inpcb.inp_laddr6.s6_addr);

                sigar_net_address6_set(conn.remote_address,
                                       &inpcb.inp_faddr6.s6_addr);
            }
#endif
            else {
                sigar_net_address_set(conn.local_address,
                                      inpcb.inp_laddr.s_addr);

                sigar_net_address_set(conn.remote_address,
                                      inpcb.inp_faddr.s_addr);
            }

            conn.local_port  = ntohs(inpcb.inp_lport);
            conn.remote_port = ntohs(inpcb.inp_fport);
            conn.receive_queue = socket.so_rcv.sb_cc;
            conn.send_queue    = socket.so_snd.sb_cc;
            conn.uid           = socket.so_pgid;
            conn.type = type;

            if (!istcp) {
                conn.state = SIGAR_TCP_UNKNOWN;
                if (walker->add_connection(walker, &conn) != SIGAR_OK) {
                    break;
                }
                continue;
            }

            conn.state = net_connection_state_get(tcpcb.t_state);

            if (walker->add_connection(walker, &conn) != SIGAR_OK) {
                break;
            }
        }
    }

    return SIGAR_OK;
}
#else
static int net_connection_get(sigar_net_connection_walker_t *walker, int proto)
{
    int flags = walker->flags;
    int type, istcp = 0;
    char *buf;
    const char *mibvar;
    struct tcpcb *tp = NULL;
    struct inpcb *inp;
    struct xinpgen *xig, *oxig;
    struct xsocket *so;
    size_t len;

    switch (proto) {
      case IPPROTO_TCP:
        mibvar = "net.inet.tcp.pcblist";
        istcp = 1;
        type = SIGAR_NETCONN_TCP;
        break;
      case IPPROTO_UDP:
        mibvar = "net.inet.udp.pcblist";
        type = SIGAR_NETCONN_UDP;
        break;
      default:
        mibvar = "net.inet.raw.pcblist";
        type = SIGAR_NETCONN_RAW;
        break;
    }

    len = 0;
    if (sysctlbyname(mibvar, 0, &len, 0, 0) < 0) {
        return errno;
    }
    if ((buf = malloc(len)) == 0) {
        return errno;
    }
    if (sysctlbyname(mibvar, buf, &len, 0, 0) < 0) {
        free(buf);
        return errno;
    }

    oxig = xig = (struct xinpgen *)buf;
    for (xig = (struct xinpgen *)((char *)xig + xig->xig_len);
         xig->xig_len > sizeof(struct xinpgen);
         xig = (struct xinpgen *)((char *)xig + xig->xig_len))
    {
        if (istcp) {
            struct xtcpcb *cb = (struct xtcpcb *)xig;
            tp = &cb->xt_tp;
            inp = &cb->xt_inp;
            so = &cb->xt_socket;
        }
        else {
            struct xinpcb *cb = (struct xinpcb *)xig;
            inp = &cb->xi_inp;
            so = &cb->xi_socket;
        }

        if (so->xso_protocol != proto) {
            continue;
        }

        if (inp->inp_gencnt > oxig->xig_gen) {
            continue;
        }

        if ((((flags & SIGAR_NETCONN_SERVER) && so->so_qlimit) ||
            ((flags & SIGAR_NETCONN_CLIENT) && !so->so_qlimit)))
        {
            sigar_net_connection_t conn;

            SIGAR_ZERO(&conn);

            if (inp->inp_vflag & INP_IPV6) {
                sigar_net_address6_set(conn.local_address,
                                       &inp->in6p_laddr.s6_addr);

                sigar_net_address6_set(conn.remote_address,
                                       &inp->in6p_faddr.s6_addr);
            }
            else {
                sigar_net_address_set(conn.local_address,
                                      inp->inp_laddr.s_addr);

                sigar_net_address_set(conn.remote_address,
                                      inp->inp_faddr.s_addr);
            }

            conn.local_port  = ntohs(inp->inp_lport);
            conn.remote_port = ntohs(inp->inp_fport);
            conn.receive_queue = so->so_rcv.sb_cc;
            conn.send_queue    = so->so_snd.sb_cc;
            conn.uid           = so->so_pgid;
            conn.type = type;

            if (!istcp) {
                conn.state = SIGAR_TCP_UNKNOWN;
                if (walker->add_connection(walker, &conn) != SIGAR_OK) {
                    break;
                }
                continue;
            }

            conn.state = net_connection_state_get(tp->t_state);

            if (walker->add_connection(walker, &conn) != SIGAR_OK) {
                break;
            }
        }
    }

    free(buf);

    return SIGAR_OK;
}
#endif

int sigar_net_connection_walk(sigar_net_connection_walker_t *walker)
{
    int flags = walker->flags;
    int status;

    if (flags & SIGAR_NETCONN_TCP) {
        status = net_connection_get(walker, IPPROTO_TCP);
        if (status != SIGAR_OK) {
            return status;
        }
    }
    if (flags & SIGAR_NETCONN_UDP) {
        status = net_connection_get(walker, IPPROTO_UDP);
        if (status != SIGAR_OK) {
            return status;
        }
    }

    return SIGAR_OK;
}

SIGAR_DECLARE(int)
sigar_net_listeners_get(sigar_net_connection_walker_t *walker)
{
	int i, status;

	status = sigar_net_connection_walk(walker);

	if (status != SIGAR_OK) {
		return status;
	}

	sigar_net_connection_list_t *list = walker->data;

	sigar_pid_t pid;
	for (i = 0; i < list->number; i++) {
		status = sigar_proc_port_get(walker->sigar, walker->flags,
			list->data[i].local_port, &pid);

		if (status == SIGAR_OK) {
			list->data[i].pid = pid;
		}
	}

	return SIGAR_OK;
}

SIGAR_DECLARE(int)
sigar_tcp_get(sigar_t *sigar,
              sigar_tcp_t *tcp)
{
    struct tcpstat mib;
#if !defined(TCPCTL_STATS) && (defined(__OpenBSD__) || defined(__NetBSD__))
    int status =
        kread(sigar, &mib, sizeof(mib),
              sigar->koffsets[KOFFSET_TCPSTAT]);
    if (status != SIGAR_OK) {
        return status;
    }
#else
    int var[4] = { CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_STATS };
    size_t len = sizeof(mib);

    if (sysctl(var, NMIB(var), &mib, &len, NULL, 0) < 0) {
        return errno;
    }
#endif

    tcp->active_opens = mib.tcps_connattempt;
    tcp->passive_opens = mib.tcps_accepts;
    tcp->attempt_fails = mib.tcps_conndrops;
    tcp->estab_resets = mib.tcps_drops;
    if (sigar_tcp_curr_estab(sigar, tcp) != SIGAR_OK) {
        tcp->curr_estab = -1;
    }
    tcp->in_segs = mib.tcps_rcvtotal;
    tcp->out_segs = mib.tcps_sndtotal - mib.tcps_sndrexmitpack;
    tcp->retrans_segs = mib.tcps_sndrexmitpack;
    tcp->in_errs =
        mib.tcps_rcvbadsum +
        mib.tcps_rcvbadoff +
        mib.tcps_rcvmemdrop +
        mib.tcps_rcvshort;
    tcp->out_rsts = -1; /* XXX mib.tcps_sndctrl - mib.tcps_closed; ? */

    return SIGAR_OK;
}

#ifndef SIGAR_FREEBSD5_NFSSTAT
static int get_nfsstats(struct nfsstats *stats)
{
    size_t len = sizeof(*stats);
    int mib[] = { CTL_VFS, 2, NFS_NFSSTATS };

    if (sysctl(mib, NMIB(mib), stats, &len, NULL, 0) < 0) {
        return errno;
    }
    else {
        return SIGAR_OK;
    }
}
#endif

typedef int rpc_cnt_t;

static void map_nfs_stats(sigar_nfs_v3_t *nfs, rpc_cnt_t *rpc)
{
    nfs->null = rpc[NFSPROC_NULL];
    nfs->getattr = rpc[NFSPROC_GETATTR];
    nfs->setattr = rpc[NFSPROC_SETATTR];
    nfs->lookup = rpc[NFSPROC_LOOKUP];
    nfs->access = rpc[NFSPROC_ACCESS];
    nfs->readlink = rpc[NFSPROC_READLINK];
    nfs->read = rpc[NFSPROC_READ];
    nfs->write = rpc[NFSPROC_WRITE];
    nfs->create = rpc[NFSPROC_CREATE];
    nfs->mkdir = rpc[NFSPROC_MKDIR];
    nfs->symlink = rpc[NFSPROC_SYMLINK];
    nfs->mknod = rpc[NFSPROC_MKNOD];
    nfs->remove = rpc[NFSPROC_REMOVE];
    nfs->rmdir = rpc[NFSPROC_RMDIR];
    nfs->rename = rpc[NFSPROC_RENAME];
    nfs->link = rpc[NFSPROC_LINK];
    nfs->readdir = rpc[NFSPROC_READDIR];
    nfs->readdirplus = rpc[NFSPROC_READDIRPLUS];
    nfs->fsstat = rpc[NFSPROC_FSSTAT];
    nfs->fsinfo = rpc[NFSPROC_FSINFO];
    nfs->pathconf = rpc[NFSPROC_PATHCONF];
    nfs->commit = rpc[NFSPROC_COMMIT];
}

int sigar_nfs_client_v2_get(sigar_t *sigar,
                            sigar_nfs_client_v2_t *nfs)
{
    return SIGAR_ENOTIMPL;
}

int sigar_nfs_server_v2_get(sigar_t *sigar,
                            sigar_nfs_server_v2_t *nfs)
{
    return SIGAR_ENOTIMPL;
}

int sigar_nfs_client_v3_get(sigar_t *sigar,
                            sigar_nfs_client_v3_t *nfs)
{
#ifdef SIGAR_FREEBSD5_NFSSTAT
    struct nfsstats stats;
    size_t size = sizeof(stats);

    if (sysctlbyname("vfs.nfs.nfsstats", &stats, &size, NULL, 0) == -1) {
        return errno;
    }

    map_nfs_stats((sigar_nfs_v3_t *)nfs, &stats.rpccnt[0]);
#else
    int status;
    struct nfsstats stats;

    if ((status = get_nfsstats(&stats)) != SIGAR_OK) {
        return status;
    }

    map_nfs_stats((sigar_nfs_v3_t *)nfs, &stats.rpccnt[0]);
#endif

    return SIGAR_OK;
}

int sigar_nfs_server_v3_get(sigar_t *sigar,
                            sigar_nfs_server_v3_t *nfs)
{
#ifdef SIGAR_FREEBSD5_NFSSTAT
    struct nfsrvstats stats;
    size_t size = sizeof(stats);

    if (sysctlbyname("vfs.nfsrv.nfsrvstats", &stats, &size, NULL, 0) == -1) {
        return errno;
    }

    map_nfs_stats((sigar_nfs_v3_t *)nfs, &stats.srvrpccnt[0]);
#else
    int status;
    struct nfsstats stats;

    if ((status = get_nfsstats(&stats)) != SIGAR_OK) {
        return status;
    }

    map_nfs_stats((sigar_nfs_v3_t *)nfs, &stats.srvrpccnt[0]);
#endif

    return SIGAR_OK;
}

static char *get_hw_type(int type)
{
    switch (type) {
    case IFT_ETHER:
        return "ether";
    case IFT_ISO88025:
        return "tr";
    case IFT_FDDI:
        return "fddi";
    case IFT_ATM:
        return "atm";
    case IFT_L2VLAN:
        return "vlan";
    case IFT_IEEE1394:
        return "firewire";
#ifdef IFT_BRIDGE
    case IFT_BRIDGE:
        return "bridge";
#endif
    default:
        return "unknown";
    }
}

int sigar_arp_list_get(sigar_t *sigar,
                       sigar_arp_list_t *arplist)
{
    size_t needed;
    char *lim, *buf, *next;
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;
    int mib[] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO };

    if (sysctl(mib, NMIB(mib), NULL, &needed, NULL, 0) < 0) {
        return errno;
    }

    if (needed == 0) { /* empty cache */
        return 0;
    }

    buf = malloc(needed);

    if (sysctl(mib, NMIB(mib), buf, &needed, NULL, 0) < 0) {
        free(buf);
        return errno;
    }

    sigar_arp_list_create(arplist);

    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {
        sigar_arp_t *arp;

        SIGAR_ARP_LIST_GROW(arplist);
        arp = &arplist->data[arplist->number++];

        rtm = (struct rt_msghdr *)next;
        sin = (struct sockaddr_inarp *)(rtm + 1);
        sdl = (struct sockaddr_dl *)((char *)sin + SA_SIZE(sin));

        sigar_net_address_set(arp->address, sin->sin_addr.s_addr);
        sigar_net_address_mac_set(arp->hwaddr, LLADDR(sdl), sdl->sdl_alen);
        if_indextoname(sdl->sdl_index, arp->ifname);
        arp->flags = rtm->rtm_flags;

        SIGAR_SSTRCPY(arp->type, get_hw_type(sdl->sdl_type));
    }

    free(buf);

    return SIGAR_OK;
}

#if (__FreeBSD_version < 800000)

#define _KERNEL
#include <sys/file.h>
#undef _KERNEL

/* derived from
 * /usr/ports/security/pidentd/work/pidentd-3.0.16/src/k_freebsd2.c
 */
int sigar_proc_port_get(sigar_t *sigar, int protocol,
                        unsigned long port, sigar_pid_t *pid)
{
    struct nlist nl[2];
    struct inpcbhead tcb;
    struct socket *sockp = NULL;
    struct kinfo_proc *pinfo;
    struct inpcb *head, pcbp;
    int i, nentries, status;

    if (protocol != SIGAR_NETCONN_TCP) {
        return SIGAR_ENOTIMPL;
    }

    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    nl[0].n_name = "_tcb"; /* XXX cache */
    nl[1].n_name = "";
    if (kvm_nlist(sigar->kmem, nl) < 0) {
        return errno;
    }

    status = kread(sigar, &tcb, sizeof(tcb), nl[0].n_value);
    if (status != SIGAR_OK) {
        return status;
    }

    for (head = tcb.lh_first; head != NULL;
         head = pcbp.inp_list.le_next)
    {
        status = kread(sigar, &pcbp, sizeof(pcbp), (long)head);
        if (status != SIGAR_OK) {
            return status;
        }
        if (!(pcbp.inp_vflag & INP_IPV4)) {
            continue;
        }
        if (pcbp.inp_fport != 0) {
            continue;
        }
        if (ntohs(pcbp.inp_lport) == port) {
            sockp = pcbp.inp_socket;
            break;
        }
    }

    if (!sockp) {
        return ENOENT;
    }

    pinfo = kvm_getprocs(sigar->kmem, KERN_PROC_PROC, 0, &nentries);
    if (!pinfo) {
        return errno;
    }

    for (i=0; i<nentries; i++) {
        if (pinfo[i].KI_FLAG & P_SYSTEM) {
            continue;
        }
        if (pinfo[i].KI_FD) {
            struct filedesc pfd;
            struct file **ofiles, ofile;
            int j, osize;

            status = kread(sigar, &pfd, sizeof(pfd), (long)pinfo[i].KI_FD);
            if (status != SIGAR_OK) {
                return status;
            }

            osize = pfd.fd_nfiles * sizeof(struct file *);
            ofiles = malloc(osize); /* XXX reuse */
            if (!ofiles) {
                return errno;
            }

            status = kread(sigar, ofiles, osize, (long)pfd.fd_ofiles);
            if (status != SIGAR_OK) {
                free(ofiles);
                return status;
            }

            for (j=0; j<pfd.fd_nfiles; j++) {
                if (!ofiles[j]) {
                    continue;
                }

                status = kread(sigar, &ofile, sizeof(ofile), (long)ofiles[j]);
                if (status != SIGAR_OK) {
                    free(ofiles);
                    return status;
                }

                if (ofile.f_count == 0) {
                    continue;
                }

                if (ofile.f_type == DTYPE_SOCKET &&
                    (struct socket *)ofile.f_data == sockp)
                {
                    *pid = pinfo[i].KI_PID;
                    free(ofiles);
                    return SIGAR_OK;
                }
            }

            free(ofiles);
        }
    }

    return ENOENT;
}

#else

int sigar_proc_port_get(sigar_t *sigar, int protocol,
                        unsigned long port, sigar_pid_t *pid)
{
    return SIGAR_ENOTIMPL;
}
#endif

int sigar_os_sys_info_get(sigar_t *sigar,
                          sigar_sys_info_t *sysinfo)
{
    char *ptr;

    SIGAR_SSTRCPY(sysinfo->name, "FreeBSD");
    SIGAR_SSTRCPY(sysinfo->vendor_name, sysinfo->name);
    SIGAR_SSTRCPY(sysinfo->vendor, sysinfo->name);
    SIGAR_SSTRCPY(sysinfo->vendor_version,
                  sysinfo->version);

    if ((ptr = strstr(sysinfo->vendor_version, "-"))) {
        /* STABLE, RELEASE, CURRENT */
        *ptr++ = '\0';
        SIGAR_SSTRCPY(sysinfo->vendor_code_name, ptr);
    }

    snprintf(sysinfo->description,
             sizeof(sysinfo->description),
             "%s %s",
             sysinfo->name, sysinfo->version);

    return SIGAR_OK;
}

int sigar_os_is_in_container(sigar_t *sigar)
{
    return 0;
}
