#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/automation.h"
#include "../src/log.h"
#include "test.h"

static char *
write_script(const char *source) {
    char *path = strdup("/tmp/openmmg-automation-XXXXXX");
    if (path == NULL) {
        return NULL;
    }

    int fd = mkstemp(path);
    if (fd < 0) {
        free(path);
        return NULL;
    }

    FILE *file = fdopen(fd, "w");
    if (file == NULL) {
        close(fd);
        unlink(path);
        free(path);
        return NULL;
    }

    fputs(source, file);
    fclose(file);
    return path;
}

void
test_automation_callbacks(void) {
    set_logfile("/dev/null");
    char *path = write_script(
        "function on_mqtt_connected(event)\n"
        "  if event.name ~= 'mqtt_connected' then error('bad event') end\n"
        "  gateway.log('connected')\n"
        "end\n"
        "function on_mqtt_disconnected(event)\n"
        "  if event.reason ~= 'test disconnect' then error('bad reason') end\n"
        "end\n");
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    CU_ASSERT_EQUAL(automation_init(path), 0);
    CU_ASSERT_EQUAL(automation_emit_mqtt_connected(), 0);
    CU_ASSERT_EQUAL(automation_emit_mqtt_disconnected("test disconnect"), 0);
    automation_shutdown();

    unlink(path);
    free(path);
}

void
test_automation_instruction_limit(void) {
    set_logfile("/dev/null");
    char *path = write_script("function on_mqtt_connected(event)\n"
                              "  while true do end\n"
                              "end\n");
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    CU_ASSERT_EQUAL(automation_init(path), 0);
    CU_ASSERT_NOT_EQUAL(automation_emit_mqtt_connected(), 0);
    automation_shutdown();

    unlink(path);
    free(path);
}

void
test_automation_request_hooks(void) {
    set_logfile("/dev/null");
    char *path = write_script(
        "function on_before_read(request)\n"
        "  request.address = 7\n"
        "  request.count = 2\n"
        "end\n"
        "function on_before_read_registers(request)\n"
        "  if request.function ~= 3 then error('wrong request') end\n"
        "end\n"
        "function on_after_read_registers(response)\n"
        "  response.values[1] = 99\n"
        "end\n"
        "function on_before_write(request)\n"
        "  return false, 'writes are disabled'\n"
        "end\n");
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    request_t request;
    config_t config;
    memset(&request, 0, sizeof(request));
    memset(&config, 0, sizeof(config));
    request.function = 3;
    request.register_addr = 1;
    request.register_count = 1;

    CU_ASSERT_EQUAL(automation_init(path), 0);
    char reason[64] = {0};
    CU_ASSERT_EQUAL(
        automation_intercept_request(&config, &request, reason, sizeof(reason)),
        0);
    CU_ASSERT_EQUAL(request.register_addr, 6);
    CU_ASSERT_EQUAL(request.register_count, 2);
    request.data[0] = 12;
    CU_ASSERT_EQUAL(automation_transform_response(&request), 0);
    CU_ASSERT_EQUAL(request.data[0], 99);

    request.function = 16;
    CU_ASSERT_EQUAL(
        automation_intercept_request(&config, &request, reason, sizeof(reason)),
        1);
    CU_ASSERT_STRING_EQUAL(reason, "writes are disabled");
    automation_shutdown();
    unlink(path);
    free(path);
}
