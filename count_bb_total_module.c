#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "modules.h"
#include <string.h>

#define NUM_THREAD_MODULE_CACHE 2

// Global variables
static int bb_counter;
static module_table_t *mod_table;
static module_entry_t *mod_cache[NUM_THREAD_MODULE_CACHE];
static const char *target_mod;

// Function prototypes for events
static void
event_exit(void);
static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded);
static void
event_module_unload(void *drcontext, const module_data_t *info);
static dr_emit_flags_t
event_bb_instrumentation(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                         bool for_trace, bool translating, void *user_data);

// Called on process start
DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_printf("Process started\n");

    // Initialization
    drmgr_init();
    bb_counter = 0;
    memset(mod_cache, 0, sizeof(mod_cache));
    mod_table = module_table_create();

    // Get target module
    if (argc < 2)
    {
        dr_printf("Need target module\n");
        return;
    }
    target_mod = argv[1];
    dr_printf("Target module: %s\n", target_mod);

    // Register functions for events
    drmgr_register_bb_instrumentation_event(NULL, event_bb_instrumentation, NULL);
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);
}

// Called when loading module
static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    module_table_load(mod_table, info);
}

// Called whe unloading module
static void
event_module_unload(void *drcontext, const module_data_t *info)
{
    module_table_unload(mod_table, info);
}

// Called on process end
static void
event_exit(void)
{
    dr_printf("Process exited\n");
    dr_printf("Total basic blocks: %d\n", bb_counter);

    // Free drmgr resources
    drmgr_exit();
    module_table_destroy(mod_table);
}

// Called on new BB
static dr_emit_flags_t
event_bb_instrumentation(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                         bool for_trace, bool translating, void *user_data)
{
    // Initialization
    app_pc start_pc;
    module_entry_t *mod_entry;
    const char *mod_name;

    // Needed to ensure instrumention unconditionally executes
    drmgr_disable_auto_predication(drcontext, bb);

    // Only instrument if first instruction of BB
    if (!drmgr_is_first_instr(drcontext, inst))
    {
        return DR_EMIT_DEFAULT;
    }

    // Get module name
    start_pc = dr_fragment_app_pc(tag);
    mod_entry = module_table_lookup(mod_cache, NUM_THREAD_MODULE_CACHE, mod_table, start_pc);
    if (mod_entry == NULL || mod_entry->data == NULL)
    {
        return DR_EMIT_DEFAULT;
    }
    mod_name = dr_module_preferred_name(mod_entry->data);

    // Check if BB should be instrumented
    if (strcmp(mod_name, target_mod) != 0)
    {
        return DR_EMIT_DEFAULT | DR_EMIT_PERSISTABLE;
    }

    // Reserve flags
    drreg_reserve_aflags(drcontext, bb, inst);

    // Increment global counter
    instrlist_meta_preinsert(bb, inst, INSTR_CREATE_inc(drcontext, OPND_CREATE_ABSMEM(&bb_counter, OPSZ_4)));

    // Unreserve flags
    drreg_unreserve_aflags(drcontext, bb, inst);

    return DR_EMIT_DEFAULT;
}