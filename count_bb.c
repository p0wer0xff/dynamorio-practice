#include "dr_api.h"
#include "drmgr.h"

// Global variable
static int bb_counter;

// Function prototypes for events
static void
event_exit(void);
static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                  bool translating, OUT void **user_data);

// Called on process start
DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_printf("Process started\n");

    // Initialization
    drmgr_init();
    bb_counter = 0;

    // Register functions for events
    drmgr_register_bb_instrumentation_event(event_bb_analysis, NULL, NULL);
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
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                  bool translating, OUT void **user_data)
{
    bb_counter++;
    return DR_EMIT_DEFAULT;
}