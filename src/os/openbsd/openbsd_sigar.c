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
#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/vmmeter.h>
#include <fcntl.h>
#include <stdio.h>

#include <nfs/nfs.h>

#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/sched.h>
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

#define KI_FD   kp_proc.p_fd
#define KI_PID  p_pid
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
#define KI_FLAG p_eflag
#define KI_START kp_proc.p_starttime

#define PROCFS_STATUS(status) \
    ((((status) != SIGAR_OK) && !sigar->proc_mounted) ? \
     SIGAR_ENOTIMPL : status)

static int get_koffsets(sigar_t *sigar)
{
    int i;
    struct nlist klist[] = {
        { "_cp_time" },
        { "_cnt" },
        { "_tcpstat" },
        { "_tcbtable" },
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

    (*sigar)->kmem = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
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
    (*sigar)->ticks = sysconf(_SC_CLK_TCK);
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

static int sigar_vmstat(sigar_t *sigar, struct uvmexp *vmstat)
{
    size_t size = sizeof(*vmstat);
    int mib[] = { CTL_VM, VM_UVMEXP };
    if (sysctl(mib, NMIB(mib), vmstat, &size, NULL, 0) < 0) {
        return errno;
    }
    else {
        return SIGAR_OK;
    }
}

int sigar_mem_get(sigar_t *sigar, sigar_mem_t *mem)
{
    sigar_uint64_t kern = 0;
    unsigned long mem_total;
    struct uvmexp vmstat;
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

    if ((status = sigar_vmstat(sigar, &vmstat)) != SIGAR_OK) {
        return status;
    }
    mem->free = vmstat.free;
    kern = vmstat.inactive;
    kern += vmstat.vnodepages + vmstat.vtextpages;
    kern *= sigar->pagesize;

    mem->used = mem->total - mem->free;

    mem->actual_free = mem->free + kern;
    mem->actual_used = mem->used - kern;

    sigar_mem_calc_ram(sigar, mem);

    return SIGAR_OK;
}

#define SWI_MAXMIB 3

#define getswapinfo_sysctl(swap_ary, swap_max) SIGAR_ENOTIMPL

#define SIGAR_FS_BLOCKS_TO_BYTES(val, bsize) ((val * bsize) >> 1)

int sigar_swap_get(sigar_t *sigar, sigar_swap_t *swap)
{
    int status;
    struct uvmexp vmstat;

    if ((status = sigar_vmstat(sigar, &vmstat)) != SIGAR_OK) {
        return status;
    }
    swap->total = vmstat.swpages * sigar->pagesize;
    swap->used = vmstat.swpginuse * sigar->pagesize;
    swap->free  = swap->total - swap->used;
    swap->page_in = vmstat.pageins;
    swap->page_out = vmstat.pdpageouts;

    return SIGAR_OK;
}

#ifndef KERN_CPTIME
#define KERN_CPTIME KERN_CP_TIME
#endif

typedef time_t cp_time_t;

int sigar_cpu_get(sigar_t *sigar, sigar_cpu_t *cpu)
{
    int status;
    cp_time_t cp_time[CPUSTATES];
    size_t size = sizeof(cp_time);

    int mib[] = { CTL_KERN, KERN_CPTIME };
    if (sysctl(mib, NMIB(mib), &cp_time, &size, NULL, 0) == -1) {
        status = errno;
    } else {
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

int sigar_os_proc_list_get(sigar_t *sigar,
                           sigar_proc_list_t *proclist)
{
    int i, num;
    struct kinfo_proc *proc;

    if (!sigar->kmem) {
        return SIGAR_EPERM_KMEM;
    }

    proc = kvm_getprocs(sigar->kmem, KERN_PROC_ALL, 0, sizeof(*proc), &num);

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

    return SIGAR_OK;
}

static int sigar_get_pinfo(sigar_t *sigar, sigar_pid_t pid)
{
	/*
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    */

    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0, sizeof(*sigar->pinfo), 1 };
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
        (pinfo->p_vm_tsize + pinfo->p_vm_dsize + pinfo->p_vm_ssize) * sigar->pagesize;

    procmem->resident = pinfo->p_vm_rssize * sigar->pagesize;

    procmem->share = SIGAR_FIELD_NOTIMPL;

    procmem->minor_faults = pinfo->p_uru_minflt;
    procmem->major_faults = pinfo->p_uru_majflt;
    procmem->page_faults  = procmem->minor_faults + procmem->major_faults;

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

    proccred->uid  = pinfo->p_ruid;
    proccred->gid  = pinfo->p_rgid;
    proccred->euid = pinfo->p_uid;
    proccred->egid = pinfo->p_gid;

    return SIGAR_OK;
}

#define tv2msec(tv) \
   (((sigar_uint64_t)tv.tv_sec * SIGAR_MSEC) + (((sigar_uint64_t)tv.tv_usec) / 1000))

int sigar_proc_time_get(sigar_t *sigar, sigar_pid_t pid,
                        sigar_proc_time_t *proctime)
{
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;

    if (status != SIGAR_OK) {
        return status;
    }

    /* XXX *_usec */
    proctime->user  = pinfo->p_uutime_sec * SIGAR_MSEC;
    proctime->sys   = pinfo->p_ustime_sec * SIGAR_MSEC;
    proctime->total = proctime->user + proctime->sys;
    proctime->start_time = pinfo->p_ustart_sec * SIGAR_MSEC;

    return SIGAR_OK;
}

int sigar_proc_state_get(sigar_t *sigar, sigar_pid_t pid,
                         sigar_proc_state_t *procstate)
{
    int status = sigar_get_pinfo(sigar, pid);
    bsd_pinfo_t *pinfo = sigar->pinfo;
    int state = pinfo->p_stat;

    if (status != SIGAR_OK) {
        return status;
    }

    SIGAR_SSTRCPY(procstate->name, pinfo->p_comm);
    procstate->ppid     = pinfo->p_ppid;
    procstate->priority = pinfo->p_priority;
    procstate->nice     = pinfo->p_nice;
    procstate->tty      = pinfo->p_tdev;
    procstate->threads  = SIGAR_FIELD_NOTIMPL;
    procstate->processor = pinfo->p_cpuid;

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
    char buffer[ARG_MAX+1], **ptr=(char **)buffer;
    size_t len = sizeof(buffer);
    int mib[] = { CTL_KERN, KERN_PROC_ARGS, 0, KERN_PROC_ARGV };
    mib[2] = pid;

    if (sysctl(mib, NMIB(mib), buffer, &len, NULL, 0) < 0) {
        return errno;
    }

    if (len == 0) {
        procargs->number = 0;
        return SIGAR_OK;
    }

    for (; *ptr; ptr++) {
        int alen = strlen(*ptr)+1;
        char *arg = malloc(alen);

        SIGAR_PROC_ARGS_GROW(procargs);
        memcpy(arg, *ptr, alen);

        procargs->data[procargs->number++] = arg;
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

    pinfo = kvm_getprocs(sigar->kmem, KERN_PROC_PID, pid, sizeof(*pinfo), &num);
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
    return SIGAR_ENOTIMPL;
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

#define sigar_statfs statfs
#define sigar_getfsstat getfsstat
#define sigar_f_flags f_flags

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
    SIGAR_DISK_STATS_INIT(disk);
    return SIGAR_ENOTIMPL;
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

    /*XXX OpenBSD*/
    mhz = SIGAR_FIELD_NOTIMPL;
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
    if (1) {
        int mib[] = { CTL_HW, HW_MODEL };
        size = sizeof(model);
        if (sysctl(mib, NMIB(mib), &model[0], &size, NULL, 0) < 0) {
            strlcpy(model, "Unknown", sizeof(model));
        }
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

static int net_connection_get(sigar_net_connection_walker_t *walker, int proto)
{
    return SIGAR_ENOTIMPL;

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
        (struct inpcb *)&TAILQ_FIRST(&((struct inpcbtable *)offset)->inpt_queue);

    next = (struct inpcb *)TAILQ_FIRST(&table.inpt_queue);

    while (next != head) {
        struct inpcb inpcb;
        struct tcpcb tcpcb;
        struct socket socket;

        status = kread(sigar, &inpcb, sizeof(inpcb), (long)next);
        prev = next;
        next = (struct inpcb *)TAILQ_NEXT(&inpcb, inp_queue);

        kread(sigar, &socket, sizeof(socket), (u_long)inpcb.inp_socket);

        if ((((flags & SIGAR_NETCONN_SERVER) && socket.so_qlimit) ||
            ((flags & SIGAR_NETCONN_CLIENT) && !socket.so_qlimit)))
        {
            sigar_net_connection_t conn;

            SIGAR_ZERO(&conn);

            if (istcp) {
                kread(sigar, &tcpcb, sizeof(tcpcb), (u_long)inpcb.inp_ppcb);
            }

            if (inpcb.inp_flags & INP_IPV6) {
                sigar_net_address6_set(conn.local_address,
                                       &inpcb.inp_laddr6.s6_addr);

                sigar_net_address6_set(conn.remote_address,
                                       &inpcb.inp_faddr6.s6_addr);
            } else {
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
    int status =
        kread(sigar, &mib, sizeof(mib),
              sigar->koffsets[KOFFSET_TCPSTAT]);
    if (status != SIGAR_OK) {
        return status;
    }

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

typedef uint64_t rpc_cnt_t;

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
    int status;
    struct nfsstats stats;

    if ((status = get_nfsstats(&stats)) != SIGAR_OK) {
        return status;
    }

    map_nfs_stats((sigar_nfs_v3_t *)nfs, &stats.rpccnt[0]);

    return SIGAR_OK;
}

int sigar_nfs_server_v3_get(sigar_t *sigar,
                            sigar_nfs_server_v3_t *nfs)
{
    int status;
    struct nfsstats stats;

    if ((status = get_nfsstats(&stats)) != SIGAR_OK) {
        return status;
    }

    map_nfs_stats((sigar_nfs_v3_t *)nfs, &stats.srvrpccnt[0]);

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

int sigar_proc_port_get(sigar_t *sigar, int protocol,
                        unsigned long port, sigar_pid_t *pid)
{
    return SIGAR_ENOTIMPL;
}

int sigar_os_sys_info_get(sigar_t *sigar,
                          sigar_sys_info_t *sysinfo)
{
    char *ptr;

    SIGAR_SSTRCPY(sysinfo->name, "OpenBSD");
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
