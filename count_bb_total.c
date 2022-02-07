#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"

// Global variable
static int bb_counter;

// Function prototypes for events
static void
event_exit(void);
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

    // Register functions for events
    drmgr_register_bb_instrumentation_event(NULL, event_bb_instrumentation, NULL);
    dr_register_exit_event(event_exit);
}

// Called on process end
static void
event_exit(void)
{
    dr_printf("Process exited\n");
    dr_printf("Total basic blocks: %d\n", bb_counter);

    // Free drmgr resources
    drmgr_exit();
}

// Called on new BB
static dr_emit_flags_t
event_bb_instrumentation(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                         bool for_trace, bool translating, void *user_data)
{
    // Needed to ensure instrumention unconditionally executes
    drmgr_disable_auto_predication(drcontext, bb);

    // Only instrument if first instruction of BB
    if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;

    // Reserve flags
    drreg_reserve_aflags(drcontext, bb, inst);

    // Increment global counter
    instrlist_meta_preinsert(bb, inst, INSTR_CREATE_inc(drcontext, OPND_CREATE_ABSMEM(&bb_counter, OPSZ_4)));

    // Unreserve flags
    drreg_unreserve_aflags(drcontext, bb, inst);

    return DR_EMIT_DEFAULT;
}