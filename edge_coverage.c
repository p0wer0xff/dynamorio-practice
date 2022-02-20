#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "modules.h"
#include "hash.h"
#include <string.h>

#define MAP_SIZE 65536
#define NUM_THREAD_MODULE_CACHE 2
#define HASH_CONST 0xa5b35705

// Global variables
static module_table_t *mod_table;
static module_entry_t *mod_cache[NUM_THREAD_MODULE_CACHE];
static const char *target_mod;
static int tls_field;
static unsigned char *afl_area;

// Function prototypes for events
static void
event_exit(void);
static void
event_thread_init(void *drcontext);
static void
event_thread_exit(void *drcontext);
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
    drreg_options_t ops = {sizeof(ops), 2 /*max slots needed: aflags*/, false};
    dr_printf("Process started\n");

    // Initialization
    drmgr_init();
    drreg_init(&ops);
    memset(mod_cache, 0, sizeof(mod_cache));
    mod_table = module_table_create();
    tls_field = drmgr_register_tls_field();
    afl_area = (unsigned char *)dr_global_alloc(MAP_SIZE);
    memset(afl_area, 0, MAP_SIZE);

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
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);
}

// Called on new thread
static void
event_thread_init(void *drcontext)
{
    void **thread_data;
    thread_data = (void **)dr_thread_alloc(drcontext, sizeof(void *));
    *thread_data = 0;
    drmgr_set_tls_field(drcontext, tls_field, thread_data);
}

// Called on thread exit
static void
event_thread_exit(void *drcontext)
{
    void *data = drmgr_get_tls_field(drcontext, tls_field);
    dr_thread_free(drcontext, data, sizeof(void *));
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
    u32 cksum;
    dr_printf("Process exited\n");

    // Print hash of AFL area
    cksum = hash32(afl_area, MAP_SIZE, HASH_CONST);
    dr_printf("Hash: %x\n", cksum);

    // Free drmgr resources
    drmgr_exit();
    drreg_exit();
    module_table_destroy(mod_table);
    dr_global_free(afl_area, MAP_SIZE);
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
    uint offset;
    reg_id_t reg, reg2, reg3;
    opnd_t opnd1, opnd2;
    instr_t *new_instr;

    // Only instrument if first instruction of BB
    if (!drmgr_is_first_instr(drcontext, inst))
    {
        return DR_EMIT_DEFAULT;
    }

    // Needed to ensure instrumention unconditionally executes
    drmgr_disable_auto_predication(drcontext, bb);

    // Get module name
    start_pc = dr_fragment_app_pc(tag);
    mod_entry = module_table_lookup(mod_cache, NUM_THREAD_MODULE_CACHE, mod_table, start_pc);
    if (mod_entry == NULL || mod_entry->data == NULL)
    {
        return DR_EMIT_DEFAULT;
    }
    mod_name = dr_module_preferred_name(mod_entry->data);

    // Check if BB should be instrumented
    if (strcasecmp(mod_name, target_mod) != 0)
    {
        return DR_EMIT_DEFAULT | DR_EMIT_PERSISTABLE;
    }

    // Get new offset
    offset = (uint)(start_pc - mod_entry->data->start);
    offset &= MAP_SIZE - 1;

    // Reserve flags and registers
    drreg_reserve_aflags(drcontext, bb, inst);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg2);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg3);

    // Load pointer to previous offset into reg3
    drmgr_insert_read_tls_field(drcontext, tls_field, bb, inst, reg3);

    // Load pointer to shared memory into reg2
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_INTPTR((uint64)afl_area);
    new_instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // Load previous offset into reg
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_MEMPTR(reg3, 0);
    new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // XOR reg (previous offset) with the new offset
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_INT32(offset);
    new_instr = INSTR_CREATE_xor(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // Increment the counter in shared memory
    opnd1 = opnd_create_base_disp(reg2, reg, 1, 0, OPSZ_1);
    new_instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // Store the new offset
    offset = (offset >> 1) & (MAP_SIZE - 1);
    opnd1 = OPND_CREATE_MEMPTR(reg3, 0);
    opnd2 = OPND_CREATE_INT32(offset);
    new_instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // Unreserve flags
    drreg_unreserve_register(drcontext, bb, inst, reg3);
    drreg_unreserve_register(drcontext, bb, inst, reg2);
    drreg_unreserve_register(drcontext, bb, inst, reg);
    drreg_unreserve_aflags(drcontext, bb, inst);

    return DR_EMIT_DEFAULT;
}