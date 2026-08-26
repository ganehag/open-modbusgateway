#include <CUnit/Basic.h>

#include "../src/automation.h"

void
test_automation_disabled(void) {
    CU_ASSERT_EQUAL(automation_init(NULL), 0);
    CU_ASSERT_NOT_EQUAL(automation_init("/etc/openmmg/automation.lua"), 0);
    automation_shutdown();
}
