#ifndef AUTOMATION_H
#define AUTOMATION_H

int automation_init(const char *script_path);
void automation_shutdown(void);
int automation_emit_mqtt_connected(void);
int automation_emit_mqtt_disconnected(const char *reason);

#endif
