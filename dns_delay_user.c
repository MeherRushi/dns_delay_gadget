// dns_delay_user.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <delay_ms>\n", argv[0]);
        return 1;
    }

    // Open BPF map
    int map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/delay_config");
    if (map_fd < 0) {
        fprintf(stderr, "Error: couldn't get map fd\n");
        return 1;
    }

    // Set delay value
    __u32 key = 0;
    __u32 value = atoi(argv[1]);
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY)) {
        fprintf(stderr, "Error: couldn't update map\n");
        return 1;
    }

    printf("DNS delay set to %d ms\n", value);
    return 0;
}