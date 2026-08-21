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
    char *path = write_script(
        "function on_mqtt_connected(event)\n"
        "  while true do end\n"
        "end\n");
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    CU_ASSERT_EQUAL(automation_init(path), 0);
    CU_ASSERT_NOT_EQUAL(automation_emit_mqtt_connected(), 0);
    automation_shutdown();

    unlink(path);
    free(path);
}
