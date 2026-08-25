#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <modbus/modbus.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "automation.h"
#include "filters.h"
#include "log.h"
#include "mqtt_client.h"
#include "request.h"

#define AUTOMATION_INSTRUCTION_LIMIT 100000
#define AUTOMATION_MEMORY_LIMIT (1024U * 1024U)
#define AUTOMATION_HOOK_INTERVAL 1000
#define AUTOMATION_QUEUE_CAPACITY 64
#define AUTOMATION_TARGET_CAPACITY 64

static lua_State *automation_state;
static int instruction_budget;
static size_t automation_memory_used;
static int64_t last_timer_ms;
static const config_t *active_config;
static const request_t *active_request;
static const config_t *automation_config;

typedef struct {
    unsigned int id;
    request_t request;
} automation_target_t;

static automation_target_t targets[AUTOMATION_TARGET_CAPACITY];
static unsigned int next_target_id = 1;

typedef struct {
    const char *handler;
    const char *name;
    char reason[128];
    int error;
    int succeeded;
    request_t request;
} automation_event_t;

static automation_event_t event_queue[AUTOMATION_QUEUE_CAPACITY];
static size_t event_queue_head;
static size_t event_queue_tail;
static pthread_mutex_t event_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

#if LUA_VERSION_NUM < 502
#define LUA_OK 0
#define lua_rawlen lua_objlen

static void
automation_lua_requiref(lua_State *state,
                        const char *name,
                        lua_CFunction open_function,
                        int set_global) {
    lua_pushcfunction(state, open_function);
    lua_pushstring(state, name);
    lua_call(state, 1, 1);
    if (set_global) {
        lua_pushvalue(state, -1);
        lua_setglobal(state, name);
    }
}
#else
#define automation_lua_requiref luaL_requiref
#endif

static int64_t
automation_now_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void *
automation_lua_alloc(void *userdata,
                     void *pointer,
                     size_t old_size,
                     size_t new_size) {
    size_t *used = userdata;
    if (new_size == 0) {
        free(pointer);
        *used -= old_size;
        return NULL;
    }
    if (new_size > old_size &&
        new_size - old_size > AUTOMATION_MEMORY_LIMIT - *used) {
        return NULL;
    }
    void *result = realloc(pointer, new_size);
    if (result != NULL) {
        *used = *used - old_size + new_size;
    }
    return result;
}

static unsigned int
automation_store_target(const request_t *request) {
    for (size_t i = 0; i < AUTOMATION_TARGET_CAPACITY; i++) {
        request_t *saved = &targets[i].request;
        if (targets[i].id != 0 && saved->format == request->format &&
            saved->slave_id == request->slave_id &&
            ((request->format == 1 &&
              strcmp(saved->serial_id, request->serial_id) == 0) ||
             (request->format == 0 && saved->ip_type == request->ip_type &&
              strcmp(saved->ip, request->ip) == 0 &&
              strcmp(saved->port, request->port) == 0))) {
            return targets[i].id;
        }
    }
    size_t slot = (next_target_id - 1) % AUTOMATION_TARGET_CAPACITY;
    targets[slot].id = next_target_id++;
    targets[slot].request = *request;
    return targets[slot].id;
}

static void
automation_push_target(lua_State *state, const request_t *request) {
    lua_newtable(state);
    lua_pushinteger(state, automation_store_target(request));
    lua_setfield(state, -2, "id");
}

static int
lua_gateway_log(lua_State *state) {
    const char *message = luaL_checkstring(state, 1);
    flog(logfile, "automation: %s\n", message);
    return 0;
}

static void
lua_instruction_hook(lua_State *state, lua_Debug *debug) {
    (void)debug;
    instruction_budget -= AUTOMATION_HOOK_INTERVAL;
    if (instruction_budget <= 0) {
        luaL_error(state, "automation instruction limit exceeded");
    }
}

static int
automation_call(int nargs) {
    instruction_budget = AUTOMATION_INSTRUCTION_LIMIT;
    lua_sethook(automation_state,
                lua_instruction_hook,
                LUA_MASKCOUNT,
                AUTOMATION_HOOK_INTERVAL);
    int result = lua_pcall(automation_state, nargs, 0, 0);
    lua_sethook(automation_state, NULL, 0, 0);
    if (result != LUA_OK) {
        flog(logfile,
             "automation callback failed: %s\n",
             lua_tostring(automation_state, -1) != NULL
                 ? lua_tostring(automation_state, -1)
                 : "unknown Lua error");
        lua_pop(automation_state, 1);
        return -1;
    }
    return 0;
}

static int
automation_emit(const char *handler,
                const char *event,
                const char *reason,
                const request_t *request,
                int error) {
    if (automation_state == NULL) {
        return 0;
    }

    lua_getglobal(automation_state, handler);
    if (!lua_isfunction(automation_state, -1)) {
        lua_pop(automation_state, 1);
        return 0;
    }

    int64_t now = automation_now_ms();
    lua_newtable(automation_state);
    lua_pushstring(automation_state, event);
    lua_setfield(automation_state, -2, "name");
    lua_pushinteger(automation_state, (lua_Integer)now);
    lua_setfield(automation_state, -2, "timestamp_ms");
    if (reason != NULL) {
        lua_pushstring(automation_state, reason);
        lua_setfield(automation_state, -2, "reason");
    }
    if (error != 0) {
        lua_pushinteger(automation_state, error);
        lua_setfield(automation_state, -2, "error");
    }
    if (request != NULL) {
        lua_pushinteger(automation_state, request->cookie);
        lua_setfield(automation_state, -2, "cookie");
        lua_pushinteger(automation_state, request->format);
        lua_setfield(automation_state, -2, "format");
        lua_pushinteger(automation_state, request->slave_id);
        lua_setfield(automation_state, -2, "slave_id");
        lua_pushinteger(automation_state, request->function);
        lua_setfield(automation_state, -2, "function_code");
        lua_pushinteger(automation_state, request->register_addr + 1);
        lua_setfield(automation_state, -2, "register_address");
        lua_pushinteger(automation_state, request->register_count);
        lua_setfield(automation_state, -2, "register_count");
        if (request->format == 1) {
            lua_pushstring(automation_state, request->serial_id);
            lua_setfield(automation_state, -2, "serial_id");
        }
        uint16_t value_count =
            (request->function <= 4 || request->function == 15 ||
             request->function == 16)
                ? request->register_count
                : 0;
        lua_newtable(automation_state);
        for (uint16_t i = 0; i < value_count; i++) {
            lua_pushinteger(automation_state, request->data[i]);
            lua_rawseti(automation_state, -2, i + 1);
        }
        lua_setfield(automation_state, -2, "values");
        automation_push_target(automation_state, request);
        lua_setfield(automation_state, -2, "target");
    }

    return automation_call(1);
}

static void
automation_push_request(lua_State *state, const request_t *request) {
    lua_newtable(state);
    lua_pushinteger(state, request->cookie);
    lua_setfield(state, -2, "cookie");
    lua_pushinteger(state, request->format);
    lua_setfield(state, -2, "format");
    lua_pushinteger(state, request->slave_id);
    lua_setfield(state, -2, "slave_id");
    lua_pushinteger(state, request->function);
    lua_setfield(state, -2, "function_code");
    lua_pushinteger(state, request->register_addr + 1);
    lua_setfield(state, -2, "address");
    lua_pushinteger(state, request->register_count);
    lua_setfield(state, -2, "count");
    if (request->format == 1) {
        lua_pushstring(state, request->serial_id);
        lua_setfield(state, -2, "serial_id");
    }
    uint16_t value_count = (request->function <= 4 || request->function == 15 ||
                            request->function == 16)
                               ? request->register_count
                               : 0;
    lua_newtable(state);
    for (uint16_t i = 0; i < value_count; i++) {
        lua_pushinteger(state, request->data[i]);
        lua_rawseti(state, -2, i + 1);
    }
    lua_setfield(state, -2, "values");
}

static int
automation_request_from_table(lua_State *state, int index, request_t *request) {
    lua_getfield(state, index, "address");
    if (lua_isnumber(state, -1)) {
        lua_Integer address = lua_tointeger(state, -1);
        if (address < 1 || address > 65536) {
            lua_pop(state, 1);
            return -1;
        }
        request->register_addr = (uint32_t)address - 1;
    }
    lua_pop(state, 1);

    lua_getfield(state, index, "count");
    if (lua_isnumber(state, -1)) {
        lua_Integer count = lua_tointeger(state, -1);
        lua_Integer max_count = request->function == 6 ? UINT16_MAX : 123;
        if (request->function >= 1 && request->function <= 4) {
            max_count = 125;
        }
        if (count < 0 || count > max_count) {
            lua_pop(state, 1);
            return -1;
        }
        request->register_count = (uint16_t)count;
    }
    lua_pop(state, 1);

    lua_getfield(state, index, "values");
    if (lua_istable(state, -1)) {
        size_t count = lua_rawlen(state, -1);
        size_t max_values = request->function <= 4 ? 125 : 123;
        if (count > max_values ||
            ((request->function == 5 || request->function == 6) &&
             count != 0)) {
            lua_pop(state, 1);
            return -1;
        }
        for (size_t i = 0; i < count; i++) {
            lua_rawgeti(state, -1, (int)i + 1);
            if (!lua_isnumber(state, -1)) {
                lua_pop(state, 2);
                return -1;
            }
            lua_Integer value = lua_tointeger(state, -1);
            lua_pop(state, 1);
            if (value < 0 || value > UINT16_MAX ||
                (request->function == 15 && value > 1)) {
                lua_pop(state, 1);
                return -1;
            }
            request->data[i] = (uint16_t)value;
        }
    }
    lua_pop(state, 1);
    return 0;
}

static const char *
automation_handler_for_function(uint8_t function) {
    switch (function) {
    case 1:
        return "on_before_read_coils";
    case 2:
        return "on_before_read_discrete_inputs";
    case 3:
        return "on_before_read_registers";
    case 4:
        return "on_before_read_input_registers";
    case 5:
        return "on_before_write_coil";
    case 6:
        return "on_before_write_register";
    case 15:
        return "on_before_write_coils";
    case 16:
        return "on_before_write_registers";
    default:
        return NULL;
    }
}

static const char *
automation_after_handler_for_function(uint8_t function) {
    switch (function) {
    case 1:
        return "on_after_read_coils";
    case 2:
        return "on_after_read_discrete_inputs";
    case 3:
        return "on_after_read_registers";
    case 4:
        return "on_after_read_input_registers";
    case 5:
        return "on_after_write_coil";
    case 6:
        return "on_after_write_register";
    case 15:
        return "on_after_write_coils";
    case 16:
        return "on_after_write_registers";
    default:
        return NULL;
    }
}

static int
automation_call_interceptor(const char *handler,
                            request_t *request,
                            char *reason,
                            size_t reason_size) {
    lua_getglobal(automation_state, handler);
    if (!lua_isfunction(automation_state, -1)) {
        lua_pop(automation_state, 1);
        return 0;
    }
    automation_push_request(automation_state, request);
    lua_pushvalue(automation_state, -1);
    int table_ref = luaL_ref(automation_state, LUA_REGISTRYINDEX);
    instruction_budget = AUTOMATION_INSTRUCTION_LIMIT;
    lua_sethook(automation_state,
                lua_instruction_hook,
                LUA_MASKCOUNT,
                AUTOMATION_HOOK_INTERVAL);
    int result = lua_pcall(automation_state, 1, 2, 0);
    lua_sethook(automation_state, NULL, 0, 0);
    if (result != LUA_OK) {
        flog(logfile,
             "automation interceptor failed: %s\n",
             lua_tostring(automation_state, -1) != NULL
                 ? lua_tostring(automation_state, -1)
                 : "unknown Lua error");
        lua_pop(automation_state, 1);
        luaL_unref(automation_state, LUA_REGISTRYINDEX, table_ref);
        return -1;
    }
    if (lua_isboolean(automation_state, -2) &&
        !lua_toboolean(automation_state, -2)) {
        const char *message = lua_tostring(automation_state, -1);
        snprintf(reason,
                 reason_size,
                 "%s",
                 message != NULL ? message : "rejected by automation");
        lua_pop(automation_state, 2);
        luaL_unref(automation_state, LUA_REGISTRYINDEX, table_ref);
        return 1;
    }
    lua_pop(automation_state, 2);

    lua_rawgeti(automation_state, LUA_REGISTRYINDEX, table_ref);
    lua_getfield(automation_state, -1, "cancel");
    const char *cancel = lua_tostring(automation_state, -1);
    if (cancel != NULL) {
        snprintf(reason, reason_size, "%s", cancel);
        lua_pop(automation_state, 2);
        luaL_unref(automation_state, LUA_REGISTRYINDEX, table_ref);
        return 1;
    }
    lua_pop(automation_state, 1);
    int update_result =
        automation_request_from_table(automation_state, -1, request);
    lua_pop(automation_state, 1);
    luaL_unref(automation_state, LUA_REGISTRYINDEX, table_ref);
    return update_result;
}

static modbus_t *
automation_modbus_new_rtu(const request_t *request) {
#ifdef HAVE_MODBUS_RTU_FLOW_CONTROL
    return modbus_new_rtu(request->serial_device,
                          request->serial_baud,
                          request->serial_parity,
                          request->serial_data_bits,
                          request->serial_stop_bits,
                          0);
#else
    return modbus_new_rtu(request->serial_device,
                          request->serial_baud,
                          request->serial_parity,
                          request->serial_data_bits,
                          request->serial_stop_bits);
#endif
}

static int
automation_modbus_read_registers(modbus_t *ctx,
                                 int address,
                                 int count,
                                 uint16_t *values) {
#ifdef HAVE_MODBUS_UINT16_REGISTER_BUFFERS
    return modbus_read_registers(ctx, address, count, values);
#else
    return modbus_read_registers(ctx, address, count, (uint8_t *)values);
#endif
}

static modbus_t *
automation_open_modbus(request_t *request) {
    request_t filter_request = *request;
    filter_request.register_addr++;
    const config_t *config =
        active_config != NULL ? active_config : automation_config;
    if (config == NULL || filter_match(config->head, &filter_request) != 0) {
        return NULL;
    }

    modbus_t *ctx = request->format == 1
                        ? automation_modbus_new_rtu(request)
                        : modbus_new_tcp_pi(request->ip, request->port);
    if (ctx == NULL) {
        return NULL;
    }
    modbus_set_response_timeout(ctx, request->timeout, 0);
    modbus_set_slave(ctx, request->slave_id);
    request_transport_lock(request);
    if (modbus_connect(ctx) == -1) {
        modbus_free(ctx);
        request_transport_unlock(request);
        return NULL;
    }
    return ctx;
}

static void
automation_close_modbus(const request_t *request, modbus_t *ctx) {
    modbus_close(ctx);
    modbus_free(ctx);
    request_transport_unlock(request);
}

static int
lua_gateway_read_registers(lua_State *state) {
    lua_Integer address = luaL_checkinteger(state, 1);
    lua_Integer count = luaL_checkinteger(state, 2);
    if (active_request == NULL || address < 1 || address > 65536 || count < 1 ||
        count > 125 || address + count - 1 > 65536) {
        return luaL_error(state, "invalid Modbus read");
    }

    request_t request = *active_request;
    request.function = 3;
    request.register_addr = (uint32_t)address - 1;
    request.register_count = (uint16_t)count;
    modbus_t *ctx = automation_open_modbus(&request);
    if (ctx == NULL) {
        lua_pushnil(state);
        lua_pushstring(state,
                       "auxiliary read was blocked or could not connect");
        return 2;
    }

    uint16_t values[125];
    int result = automation_modbus_read_registers(
        ctx, request.register_addr, request.register_count, values);
    if (result == -1) {
        const char *message = modbus_strerror(errno);
        automation_close_modbus(&request, ctx);
        lua_pushnil(state);
        lua_pushstring(state, message);
        return 2;
    }
    automation_close_modbus(&request, ctx);
    lua_newtable(state);
    for (int i = 0; i < result; i++) {
        lua_pushinteger(state, values[i]);
        lua_rawseti(state, -2, i + 1);
    }
    return 1;
}

static int
lua_gateway_write_registers(lua_State *state) {
    lua_Integer address = luaL_checkinteger(state, 1);
    luaL_checktype(state, 2, LUA_TTABLE);
    size_t count = lua_rawlen(state, 2);
    if (active_request == NULL || address < 1 || address > 65536 ||
        count == 0 || count > 123 || address + count - 1 > 65536) {
        return luaL_error(state, "invalid Modbus write");
    }

    request_t request = *active_request;
    request.function = 16;
    request.register_addr = (uint32_t)address - 1;
    request.register_count = (uint16_t)count;
    for (size_t i = 0; i < count; i++) {
        lua_rawgeti(state, 2, (int)i + 1);
        if (!lua_isnumber(state, -1)) {
            return luaL_error(state, "write values must be integers");
        }
        lua_Integer value = lua_tointeger(state, -1);
        lua_pop(state, 1);
        if (value < 0 || value > UINT16_MAX) {
            return luaL_error(state, "write value is out of range");
        }
        request.data[i] = (uint16_t)value;
    }

    modbus_t *ctx = automation_open_modbus(&request);
    if (ctx == NULL) {
        lua_pushnil(state);
        lua_pushstring(state,
                       "auxiliary write was blocked or could not connect");
        return 2;
    }
    int result = modbus_write_registers(
        ctx, request.register_addr, request.register_count, request.data);
    if (result == -1) {
        const char *message = modbus_strerror(errno);
        automation_close_modbus(&request, ctx);
        lua_pushnil(state);
        lua_pushstring(state, message);
        return 2;
    }
    automation_close_modbus(&request, ctx);
    lua_pushboolean(state, 1);
    return 1;
}

static int
automation_request_from_target(lua_State *state,
                               int index,
                               request_t *request) {
    if (automation_config == NULL || !lua_istable(state, index)) {
        return -1;
    }
    lua_getfield(state, index, "id");
    unsigned int id = (unsigned int)lua_tointeger(state, -1);
    lua_pop(state, 1);
    for (size_t i = 0; i < AUTOMATION_TARGET_CAPACITY; i++) {
        if (targets[i].id == id) {
            *request = targets[i].request;
            request->timeout = automation_config->timeout;
            return 0;
        }
    }
    return -1;
}

static int
lua_gateway_write_registers_to(lua_State *state) {
    luaL_checktype(state, 1, LUA_TTABLE);
    lua_Integer address = luaL_checkinteger(state, 2);
    luaL_checktype(state, 3, LUA_TTABLE);
    size_t count = lua_rawlen(state, 3);
    if (address < 1 || address > 65536 || count == 0 || count > 123 ||
        address + count - 1 > 65536) {
        return luaL_error(state, "invalid Modbus write");
    }

    request_t request;
    if (automation_request_from_target(state, 1, &request) != 0) {
        return luaL_error(state, "invalid automation target");
    }
    request.function = 16;
    request.register_addr = (uint32_t)address - 1;
    request.register_count = (uint16_t)count;
    for (size_t i = 0; i < count; i++) {
        lua_rawgeti(state, 3, (int)i + 1);
        if (!lua_isnumber(state, -1)) {
            return luaL_error(state, "write values must be integers");
        }
        lua_Integer value = lua_tointeger(state, -1);
        lua_pop(state, 1);
        if (value < 0 || value > UINT16_MAX) {
            return luaL_error(state, "write value is out of range");
        }
        request.data[i] = (uint16_t)value;
    }

    modbus_t *ctx = automation_open_modbus(&request);
    if (ctx == NULL) {
        lua_pushnil(state);
        lua_pushstring(state,
                       "auxiliary write was blocked or could not connect");
        return 2;
    }
    int result = modbus_write_registers(
        ctx, request.register_addr, request.register_count, request.data);
    if (result == -1) {
        const char *message = modbus_strerror(errno);
        automation_close_modbus(&request, ctx);
        lua_pushnil(state);
        lua_pushstring(state, message);
        return 2;
    }
    automation_close_modbus(&request, ctx);
    lua_pushboolean(state, 1);
    return 1;
}

int
automation_intercept_request(const config_t *config,
                             request_t *request,
                             char *reason,
                             size_t reason_size) {
    if (automation_state == NULL) {
        return 0;
    }

    const char *phase =
        request->function <= 4 ? "on_before_read" : "on_before_write";
    const char *specific = automation_handler_for_function(request->function);
    const char *handlers[] = {"on_before_request", phase, specific};
    active_config = config;
    active_request = request;
    for (size_t i = 0; i < sizeof(handlers) / sizeof(handlers[0]); i++) {
        if (handlers[i] == NULL) {
            continue;
        }
        int result = automation_call_interceptor(
            handlers[i], request, reason, reason_size);
        if (result != 0) {
            active_config = NULL;
            active_request = NULL;
            return result;
        }
    }
    active_config = NULL;
    active_request = NULL;
    return 0;
}

int
automation_init(const char *script_path) {
    if (script_path == NULL || script_path[0] == '\0') {
        return 0;
    }

    automation_memory_used = 0;
    automation_state =
        lua_newstate(automation_lua_alloc, &automation_memory_used);
    if (automation_state == NULL) {
        return -1;
    }
    pthread_mutex_lock(&event_queue_mutex);
    event_queue_head = 0;
    event_queue_tail = 0;
    pthread_mutex_unlock(&event_queue_mutex);
    last_timer_ms = 0;
    memset(targets, 0, sizeof(targets));
    next_target_id = 1;

    automation_lua_requiref(automation_state, "_G", luaopen_base, 1);
    lua_pop(automation_state, 1);
    automation_lua_requiref(automation_state, "string", luaopen_string, 1);
    lua_pop(automation_state, 1);
    automation_lua_requiref(automation_state, "table", luaopen_table, 1);
    lua_pop(automation_state, 1);
    lua_pushnil(automation_state);
    lua_setglobal(automation_state, "dofile");
    lua_pushnil(automation_state);
    lua_setglobal(automation_state, "loadfile");
    lua_pushnil(automation_state);
    lua_setglobal(automation_state, "load");

    lua_newtable(automation_state);
    lua_pushcfunction(automation_state, lua_gateway_log);
    lua_setfield(automation_state, -2, "log");
    lua_pushcfunction(automation_state, lua_gateway_read_registers);
    lua_setfield(automation_state, -2, "read_registers");
    lua_pushcfunction(automation_state, lua_gateway_write_registers);
    lua_setfield(automation_state, -2, "write_registers");
    lua_pushcfunction(automation_state, lua_gateway_write_registers_to);
    lua_setfield(automation_state, -2, "write_registers_to");
    lua_setglobal(automation_state, "gateway");

    if (luaL_loadfile(automation_state, script_path) != LUA_OK ||
        automation_call(0) != 0) {
        flog(logfile, "unable to load automation script '%s'\n", script_path);
        automation_shutdown();
        return -1;
    }

    return 0;
}

void
automation_set_config(const config_t *config) {
    automation_config = config;
}

void
automation_shutdown(void) {
    if (automation_state != NULL) {
        lua_close(automation_state);
        automation_state = NULL;
    }
    automation_memory_used = 0;
    automation_config = NULL;
}

int
automation_emit_mqtt_connected(void) {
    return automation_emit(
        "on_mqtt_connected", "mqtt_connected", NULL, NULL, 0);
}

int
automation_emit_mqtt_disconnected(const char *reason) {
    return automation_emit(
        "on_mqtt_disconnected", "mqtt_disconnected", reason, NULL, 0);
}

int
automation_emit_gateway_started(void) {
    return automation_emit(
        "on_gateway_started", "gateway_started", NULL, NULL, 0);
}

int
automation_emit_gateway_stopping(void) {
    return automation_emit(
        "on_gateway_stopping", "gateway_stopping", NULL, NULL, 0);
}

int
automation_emit_request_accepted(const request_t *request) {
    return automation_emit(
        "on_request_accepted", "request_accepted", NULL, request, 0);
}

int
automation_emit_request_rejected(unsigned long long cookie, int error) {
    request_t request;
    memset(&request, 0, sizeof(request));
    request.cookie = cookie;
    return automation_emit(
        "on_request_rejected", "request_rejected", NULL, &request, error);
}

void
automation_queue_modbus_result(const request_t *request,
                               int succeeded,
                               const char *reason) {
    pthread_mutex_lock(&event_queue_mutex);
    size_t next = (event_queue_tail + 1) % AUTOMATION_QUEUE_CAPACITY;
    if (next == event_queue_head) {
        flog(logfile, "automation event queue full; dropping Modbus result\n");
        pthread_mutex_unlock(&event_queue_mutex);
        return;
    }

    automation_event_t *event = &event_queue[event_queue_tail];
    memset(event, 0, sizeof(*event));
    event->succeeded = succeeded;
    event->request = *request;
    if (reason != NULL) {
        strncpy(event->reason, reason, sizeof(event->reason) - 1);
    }
    event_queue_tail = next;
    pthread_mutex_unlock(&event_queue_mutex);
}

static int
automation_emit_after_request(request_t *request) {
    int result = 0;
    const char *phase =
        request->function <= 4 ? "on_after_read" : "on_after_write";
    const char *specific =
        automation_after_handler_for_function(request->function);
    const char *handlers[] = {"on_after_request", phase, specific};
    for (size_t i = 0; i < sizeof(handlers) / sizeof(handlers[0]); i++) {
        if (handlers[i] == NULL) {
            continue;
        }
        char ignored_reason[1] = {0};
        if (automation_call_interceptor(
                handlers[i], request, ignored_reason, sizeof(ignored_reason)) !=
            0) {
            flog(logfile, "automation after-hook rejected result\n");
            result = -1;
        }
    }
    return result;
}

int
automation_transform_response(request_t *request) {
    if (automation_state == NULL) {
        return 0;
    }
    uint32_t address = request->register_addr;
    uint16_t count = request->register_count;
    int result = automation_emit_after_request(request);
    request->register_addr = address;
    request->register_count = count;
    return result;
}

int
automation_dispatch_pending(void) {
    int result = 0;
    for (;;) {
        automation_event_t event;
        pthread_mutex_lock(&event_queue_mutex);
        if (event_queue_head == event_queue_tail) {
            pthread_mutex_unlock(&event_queue_mutex);
            return result;
        }
        event = event_queue[event_queue_head];
        event_queue_head = (event_queue_head + 1) % AUTOMATION_QUEUE_CAPACITY;
        pthread_mutex_unlock(&event_queue_mutex);

        if (event.succeeded) {
            if (automation_transform_response(&event.request) != 0) {
                result = -1;
            }
            uint32_t data_len =
                event.request.function <= 4 ? event.request.register_count : 0;
            mqtt_reply_ok(event.request.mosq,
                          event.request.response_topic,
                          event.request.cookie,
                          data_len,
                          event.request.data);
            if (automation_emit("on_modbus_succeeded",
                                "modbus_succeeded",
                                NULL,
                                &event.request,
                                0) != 0) {
                result = -1;
            }
        } else {
            mqtt_reply_error(event.request.mosq,
                             event.request.response_topic,
                             event.request.cookie,
                             MQTT_ERROR_MESSAGE,
                             event.reason[0] != '\0' ? event.reason : NULL);
            if (automation_emit("on_modbus_failed",
                                "modbus_failed",
                                event.reason[0] != '\0' ? event.reason : NULL,
                                &event.request,
                                0) != 0) {
                result = -1;
            }
        }
    }
}

int
automation_emit_timer(void) {
    int64_t now = automation_now_ms();
    if (now - last_timer_ms < 1000) {
        return 0;
    }
    last_timer_ms = now;
    return automation_emit("on_timer", "timer", NULL, NULL, 0);
}
int result = 0;
