/*
 * Copyright (c) 2008 Hyperic, Inc.
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

int main(int argc, char **argv)
{
    int status;
    sigar_t *sigar;
    sigar_sys_info_t sysinfo;

    sigar_open(&sigar);

    status = sigar_sys_info_get(sigar, &sysinfo);

    if (status != SIGAR_OK) {
        printf("sys_info error: %d (%s)\n",
               status, sigar_strerror(sigar, status));
        exit(1);
    }

    printf("name: %s\n", sysinfo.name);
    printf("version: %s\n", sysinfo.version);
    printf("arch: %s\n", sysinfo.arch);
    printf("machine: %s\n", sysinfo.machine);
    printf("description: %s\n", sysinfo.description);
    printf("patch_level: %s\n", sysinfo.patch_level);
    printf("vendor: %s\n", sysinfo.vendor);
    printf("vendor_version: %s\n", sysinfo.vendor_version);
    printf("vendor_name: %s\n", sysinfo.vendor_name);
    printf("vendor_code_name: %s\n", sysinfo.vendor_code_name);
    printf("vendor_uuid: %s\n", sysinfo.uuid);

    sigar_close(sigar);

    return 0;
}
