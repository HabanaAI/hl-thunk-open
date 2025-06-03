// SPDX-License-Identifier: MIT

/*
 * Copyright 2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#define _GNU_SOURCE

#include "hlthunk_tests.h"

#include <stdio.h>
#include <curses.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>

#define TIMEOUT_SEC	30

char *validate_device_folder(const char *path, const char *vendor_string)
{
	char file_path[1024], buffer[10];
	FILE *vendor_file;
	size_t bytes_read;
	DIR *net_dir;

	/* check for vendor file with contents equal to specified string */
	snprintf(file_path, sizeof(file_path), "%s/vendor", path);
	vendor_file = fopen(file_path, "r");

	if (!vendor_file)
		return NULL;

	bytes_read = fread(buffer, sizeof(char), sizeof(buffer) - 1, vendor_file);
	fclose(vendor_file);

	if (!bytes_read)
		return NULL;

	buffer[bytes_read] = '\0';  // null-terminate the buffer

	if (strncmp(buffer, vendor_string, strlen(vendor_string)))
		return NULL;

	/* check for "net" sub-folder inside the found folder */
	snprintf(file_path, sizeof(file_path), "%s/net", path);
	net_dir = opendir(file_path);
	if (!net_dir)
		return NULL;

	closedir(net_dir);

	return strdup(file_path);
}

char *find_device_folder(const char *base_dir, const char *folder_name)
{
	char path[1024], *found_folder = NULL, *dir_path, *subdir, **stack;
	const char *vendor_string = "0x1da3";
	struct dirent *entry;
	int top = 0;
	DIR *dir;

	/* create a stack to keep track of directories to search */
	stack = malloc(sizeof(char *) * 1024);
	if (stack == NULL) {
		perror("Error allocating memory for stack");
		return NULL;
	}

	stack[top++] = strdup(base_dir);

	while (top > 0 && found_folder == NULL) {
		dir_path = stack[--top];
		dir = opendir(dir_path);
		if (dir == NULL) {
			perror("Error opening directory");
			continue;
		}

		while ((entry = readdir(dir)) != NULL) {
			if (entry->d_type != DT_DIR)
				continue;

			if (strncmp(entry->d_name, ".", 1) == 0 ||
						strncmp(entry->d_name, "..", 2) == 0)
				continue;

			snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

			if (strncmp(entry->d_name, folder_name, strlen(folder_name)) != 0) {
				/* push subdirectories onto stack to search later */
				if (top < 1024) {
					subdir = strdup(path);
					if (subdir == NULL) {
						perror("Error allocating memory for subdir");
						return NULL;
					}
					stack[top++] = subdir;
				} else {
					printf("Stack is full, cannot push %s\n", path);
				}
				continue;
			}

			found_folder = validate_device_folder(path, vendor_string);

			/* We won't find another folder with the same name at this level */
			break;
		}

		closedir(dir);
		free(dir_path);
	}

	/* free memory used by stack */
	for (int i = 0; i < top; i++)
		free(stack[i]);

	free(stack);

	return found_folder;
}

uint64_t get_ext_ports_state_from_sysfs(const char *net_folder)
{
	char path[1024], operstate[10], dev_port_str[10];
	struct dirent *entry;
	uint64_t mask = 0;
	DIR *net_dir;
	int dev_port;

	net_dir = opendir(net_folder);
	if (net_dir == NULL) {
		perror("open net folder of device");
		return 0;
	}

	while ((entry = readdir(net_dir)) != NULL) {
		FILE *operstate_file, *dev_port_file;

		if (entry->d_type != DT_DIR || strncmp(entry->d_name, ".", 1) == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s/operstate", net_folder, entry->d_name);

		operstate_file = fopen(path, "r");
		if (operstate_file == NULL) {
			perror("fopen of operstate");
			return 0;
		}
		fgets(operstate, sizeof(operstate), operstate_file);
		fclose(operstate_file);

		operstate[strcspn(operstate, "\n")] = '\0';

		snprintf(path, sizeof(path), "%s/%s/dev_port", net_folder, entry->d_name);

		dev_port_file = fopen(path, "r");
		if (dev_port_file == NULL) {
			perror("fopen of dev_port");
			return 0;
		}
		fgets(dev_port_str, sizeof(dev_port_str), dev_port_file);
		fclose(dev_port_file);

		dev_port_str[strcspn(dev_port_str, "\n")] = '\0';

		dev_port = atoi(dev_port_str);
		if (dev_port < 0 || dev_port > 63) {
			printf("dev_port value (%d) in subfolder %s/%s is out of range (0-63)\n",
				dev_port, net_folder, entry->d_name);
			continue;
		}

		printf("Subfolder path: %s/%s (%s, %d)\n",
			net_folder, entry->d_name, operstate, dev_port);

		if (strncmp(operstate, "up", 2) == 0)
			mask |= 1ull << dev_port;
	}

	closedir(net_dir);

	return mask;
}

bool get_ext_ports_status(int fd, uint64_t ext_ports_mask, uint64_t *ext_ports_status)
{
	bool all_ext_ports_up = false;
	char pci_bus_id[128], *path_to_device_dir;
	int rc;

	*ext_ports_status = 0;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, 127);
	if (rc) {
		printf("Failed to get pci bus id %d\n", rc);
		return false;
	}

	printf("Device PCI bus id = %s\n", pci_bus_id);

	path_to_device_dir = find_device_folder("/sys/devices", pci_bus_id);
	if (!path_to_device_dir) {
		printf("Failed to find device folder in sysfs\n");
		return false;
	}

	printf("Found device folder at %s\n", path_to_device_dir);

	*ext_ports_status = get_ext_ports_state_from_sysfs(path_to_device_dir);
	free(path_to_device_dir);

	if ((*ext_ports_status & ext_ports_mask) == ext_ports_mask)
		all_ext_ports_up = true;

	printf("External ports status = 0x%lx\n", *ext_ports_status);
	printf("All external ports are %s", (all_ext_ports_up ? "up\n" : "not up\n"));

	return all_ext_ports_up;
}

bool get_int_ports_status(int fd, uint64_t int_ports_mask, uint64_t *int_ports_status)
{
	struct hlthunk_get_habana_link_state_out out;
	struct hlthunk_get_habana_link_state_in in;
	bool all_int_ports_up = true;
	int rc, i;

	*int_ports_status = 0;

	for (i = 0 ; i < 64 ; i++) {
		if (!(int_ports_mask & (1ull << i)))
			continue;

		in.port = i;

		rc = hlthunk_get_habana_link_state(fd, &in, &out);
		if (rc) {
			printf("Failed to get link %d state %d\n", i, rc);
			return false;
		}

		*int_ports_status |= (out.up << i);
		if (!out.up)
			all_int_ports_up = false;
	}

	printf("Internal ports status = 0x%lx\n", *int_ports_status);
	printf("All internal ports are %s", (all_int_ports_up ? "up\n" : "not up\n"));

	return all_int_ports_up;
}

void acquire_device_when_all_ports_are_up(int fd, enum hl_server_type server_type,
						uint32_t module_id)
{
	bool int_ports_up = false, ext_ports_up = false;
	uint64_t int_ports_status, ext_ports_status;
	uint64_t int_ports_mask, ext_ports_mask;
	uint8_t num_of_retry = 0;
	int main_fd;

	switch (server_type) {
	case HL_SERVER_GAUDI_HLS1:
		int_ports_mask = 0xfd;
		ext_ports_mask = 0x302;
		break;
	case HL_SERVER_GAUDI2_HLS2:
		int_ports_mask = 0x3ffeff;
		ext_ports_mask = 0xc00100;
		break;
	default:
		printf("This demo doesn't support server type %d\n", server_type);
		return;
	}

	int_ports_up = get_int_ports_status(fd, int_ports_mask, &int_ports_status);
	ext_ports_up = get_ext_ports_status(fd, ext_ports_mask, &ext_ports_status);

	while ((!int_ports_up || !ext_ports_up) && num_of_retry++ < TIMEOUT_SEC) {
		printf("Not all ports are up, wait for 1s and do retry no. %d\n", num_of_retry);
		sleep(1);
		int_ports_up = get_int_ports_status(fd, int_ports_mask, &int_ports_status);
		ext_ports_up = get_ext_ports_status(fd, ext_ports_mask, &ext_ports_status);
	}

	if (int_ports_up && ext_ports_up) {
		printf("All ports are up, we can acquire the device\n");
	} else {
		printf("Not all ports are up and timeout expired. Exit...\n");
		return;
	}

	main_fd = hlthunk_open_by_module_id(module_id);
	if (main_fd < 0) {
		printf("Failed to acquire main device :(\n");
		return;
	}

	/* We just wanted to open the device... */
	hlthunk_close(main_fd);
}

int main(int argc, const char **argv)
{
	struct hlthunk_hw_ip_info *hw_ip_info;
	struct hltests_state *tests_state;
	void *state;
	int rc;

	hltests_parser(argc, argv, NULL, HLTEST_DEVICE_MASK_GAUDI_FAMILY);

	rc = hltests_init();
	if (rc) {
		printf("Failed to initialize hlthunk tests library (%d)\n", rc);
		return rc;
	}

	rc = hltests_control_dev_setup(&state);
	if (rc) {
		printf("Failed to run setup phase of control device (%d)\n", rc);
		goto tests_fini;
	}

	tests_state = (struct hltests_state *) state;

	hw_ip_info = &tests_state->hw_ip;

	acquire_device_when_all_ports_are_up(tests_state->fd, hw_ip_info->server_type,
						hw_ip_info->module_id);

	hltests_control_dev_teardown(&state);
tests_fini:
	hltests_fini();

	return 0;
}
