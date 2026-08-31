#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/automation.h"
#include "../src/log.h"
#include "mqtt_test_helpers.h"
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
test_automation_memory_limit(void) {
    set_logfile("/dev/null");
    char *path =
        write_script("function on_mqtt_connected(event)\n"
                     "  local value = string.rep('x', 2 * 1024 * 1024)\n"
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
        "  if request.function_code ~= 3 then error('wrong request') end\n"
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

void
test_automation_result_queue_growth(void) {
    mqtt_test_silence_logs();
    mqtt_test_reset();
    CU_ASSERT_EQUAL(automation_init(NULL), 0);

    request_t request;
    memset(&request, 0, sizeof(request));
    request.function = 6;
    strncpy(
        request.response_topic, "response", sizeof(request.response_topic) - 1);

    automation_queue_modbus_result(NULL, 1, NULL);
    for (unsigned int i = 0; i < 1100; i++) {
        request.cookie = i;
        automation_queue_modbus_result(&request, 1, NULL);
    }
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 76);
    CU_ASSERT_EQUAL(automation_dispatch_pending(), 0);
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 1100);
    CU_ASSERT_STRING_EQUAL(mqtt_test_last_payload(), "1023 OK");
    automation_shutdown();
}

void
test_automation_rejects_invalid_edits_and_reinitializes(void) {
    mqtt_test_silence_logs();
    char *path = write_script(
        "function on_before_request(request)\n"
        "  if request.cookie == 1 then request.count = 1.5 end\n"
        "  if request.cookie == 2 then request.values[1] = '7' end\n"
        "  if request.cookie == 3 then request.count = 2 end\n"
        "  if request.cookie == 5 then gateway.write_registers(1, {1.5}) end\n"
        "  if request.cookie == 6 then gateway.write_registers(1, {'7'}) end\n"
        "end\n"
        "function on_after_read(response) response.values[1] = 88 end\n"
        "function on_after_read_registers(response) response.values[1] = 'bad' "
        "end\n"
        "function on_mqtt_connected(event) error('still enabled') end\n");
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);
    CU_ASSERT_EQUAL(automation_init(path), 0);

    config_t config;
    request_t request;
    char reason[64] = {0};
    memset(&config, 0, sizeof(config));
    memset(&request, 0, sizeof(request));
    request.function = 3;
    request.register_addr = 1;
    request.register_count = 1;

    request.cookie = 1;
    CU_ASSERT_NOT_EQUAL(
        automation_intercept_request(&config, &request, reason, sizeof(reason)),
        0);

    request.cookie = 4;
    request.function = 3;
    request.register_count = 1;
    request.data[0] = 12;
    CU_ASSERT_NOT_EQUAL(automation_transform_response(&request), 0);
    CU_ASSERT_EQUAL(request.data[0], 12);
    request.cookie = 2;
    request.register_count = 1;
    CU_ASSERT_NOT_EQUAL(
        automation_intercept_request(&config, &request, reason, sizeof(reason)),
        0);
    request.cookie = 3;
    request.function = 16;
    request.register_count = 1;
    request.data[0] = 9;
    CU_ASSERT_NOT_EQUAL(
        automation_intercept_request(&config, &request, reason, sizeof(reason)),
        0);

    request.cookie = 5;
    request.function = 3;
    request.register_count = 1;
    CU_ASSERT_NOT_EQUAL(
        automation_intercept_request(&config, &request, reason, sizeof(reason)),
        0);
    request.cookie = 6;
    CU_ASSERT_NOT_EQUAL(
        automation_intercept_request(&config, &request, reason, sizeof(reason)),
        0);

    request.cookie = 7;
    request.function = 1;
    request.register_count = 1;
    request.data[0] = 1;
    CU_ASSERT_NOT_EQUAL(automation_transform_response(&request), 0);
    CU_ASSERT_EQUAL(request.data[0], 1);

    mqtt_test_reset();
    request.cookie = 8;
    request.function = 3;
    request.register_count = 1;
    request.data[0] = 12;
    strncpy(
        request.response_topic, "response", sizeof(request.response_topic) - 1);
    automation_queue_modbus_result(&request, 1, NULL);
    CU_ASSERT_NOT_EQUAL(automation_dispatch_pending(), 0);
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 1);
    CU_ASSERT_STRING_EQUAL(mqtt_test_last_payload(),
                           "8 ERROR: response automation failed");

    CU_ASSERT_EQUAL(automation_init(NULL), 0);
    CU_ASSERT_EQUAL(automation_emit_mqtt_connected(), 0);
    automation_shutdown();
    unlink(path);
    free(path);
}
