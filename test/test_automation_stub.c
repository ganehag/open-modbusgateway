#include <CUnit/Basic.h>
#include <string.h>

#include "../src/automation.h"
#include "mqtt_test_helpers.h"

void
test_automation_disabled(void) {
    CU_ASSERT_EQUAL(automation_init(NULL), 0);
    CU_ASSERT_NOT_EQUAL(automation_init("/etc/openmmg/automation.lua"), 0);
    automation_shutdown();
}

void
test_automation_disabled_delivers_results(void) {
    mqtt_test_silence_logs();
    mqtt_test_reset();

    request_t request;
    memset(&request, 0, sizeof(request));
    request.cookie = 1234;
    request.function = 3;
    request.register_count = 2;
    request.data[0] = 10;
    request.data[1] = 20;
    strncpy(
        request.response_topic, "response", sizeof(request.response_topic) - 1);

    automation_queue_modbus_result(&request, 1, NULL);
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 1);
    CU_ASSERT_STRING_EQUAL(mqtt_test_last_topic(), "response");
    CU_ASSERT_STRING_EQUAL(mqtt_test_last_payload(), "1234 OK 10 20");

    mqtt_test_reset();
    automation_queue_modbus_result(&request, 0, "connection failed");
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 1);
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "1234 ERROR: connection failed"));
}
