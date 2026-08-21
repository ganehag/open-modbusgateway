#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "automation.h"
#include "log.h"

#define AUTOMATION_INSTRUCTION_LIMIT 100000
#define AUTOMATION_HOOK_INTERVAL 1000

static lua_State *automation_state;
static int instruction_budget;

#if LUA_VERSION_NUM < 502
#define LUA_OK 0

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
automation_emit(const char *handler, const char *event, const char *reason) {
    if (automation_state == NULL) {
        return 0;
    }

    lua_getglobal(automation_state, handler);
    if (!lua_isfunction(automation_state, -1)) {
        lua_pop(automation_state, 1);
        return 0;
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    lua_newtable(automation_state);
    lua_pushstring(automation_state, event);
    lua_setfield(automation_state, -2, "name");
    lua_pushinteger(automation_state,
                    (lua_Integer)now.tv_sec * 1000 + now.tv_nsec / 1000000);
    lua_setfield(automation_state, -2, "timestamp_ms");
    if (reason != NULL) {
        lua_pushstring(automation_state, reason);
        lua_setfield(automation_state, -2, "reason");
    }

    return automation_call(1);
}

int
automation_init(const char *script_path) {
    if (script_path == NULL || script_path[0] == '\0') {
        return 0;
    }

    automation_state = luaL_newstate();
    if (automation_state == NULL) {
        return -1;
    }

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
    lua_setglobal(automation_state, "gateway");

    if (luaL_loadfile(automation_state, script_path) != LUA_OK ||
        automation_call(0) != 0) {
        flog(logfile,
             "unable to load automation script '%s'\n",
             script_path);
        automation_shutdown();
        return -1;
    }

    return 0;
}

void
automation_shutdown(void) {
    if (automation_state != NULL) {
        lua_close(automation_state);
        automation_state = NULL;
    }
}

int
automation_emit_mqtt_connected(void) {
    return automation_emit("on_mqtt_connected", "mqtt_connected", NULL);
}

int
automation_emit_mqtt_disconnected(const char *reason) {
    return automation_emit("on_mqtt_disconnected", "mqtt_disconnected", reason);
}
