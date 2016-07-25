/*
 * Copyright (c) 2006 Hyperic, Inc.
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

#include <stdio.h>
#include <stdlib.h>

#include "sigar.h"

int main(int argc, char **argv) {
    int status, i;
    sigar_t *sigar;
    sigar_proc_list_t proclist;

    sigar_open(&sigar);

    status = sigar_proc_list_get(sigar, &proclist);

    if (status != SIGAR_OK) {
        printf("proc_list error: %d (%s)\n",
               status, sigar_strerror(sigar, status));
        exit(1);
    }

    for (i = 0; i < proclist.number; i++) {
        sigar_pid_t pid = proclist.data[i];
        sigar_proc_state_t pstate;
        sigar_proc_exe_t pexe;

        status = sigar_proc_state_get(sigar, pid, &pstate);
        if (status != SIGAR_OK) {
#ifdef DEBUG
            printf("error: %d (%s) proc_state(%d)\n",
                   status, sigar_strerror(sigar, status), pid);
#endif
            printf("%d    %s    %s\n", (int)pid, "unknown", "unknown");
            continue;
        }

        status = sigar_proc_exe_get(sigar, pid, &pexe);
        if (status != SIGAR_OK) {
#ifdef DEBUG
            printf("error: %d (%s) proc_exe(%d)\n",
                   status, sigar_strerror(sigar, status), pid);
#endif
            printf("%d    %s    %s\n", (int)pid, "unknown", pstate.name);
            continue;
        }

        printf("%d    %s    %s\n", (int)pid, pexe.arch, pstate.name);
    }

    sigar_proc_list_destroy(sigar, &proclist);

    sigar_close(sigar);

    return 0;
}
