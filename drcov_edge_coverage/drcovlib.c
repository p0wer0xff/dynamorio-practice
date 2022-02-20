/* ***************************************************************************
 * Copyright (c) 2012-2018 Google, Inc.  All rights reserved.
 * ***************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Code Coverage Library
 *
 * Collects information about basic blocks that have been executed.
 * It simply stores the information of basic blocks seen in bb callback event
 * into a table without any instrumentation, and dumps the buffer into log files
 * on thread/process exit.
 *
 * There are pros and cons to creating this coverage library as opposed to other
 * tools using the drcov client straight-up as a 2nd client: DR has support for
 * multiple clients, after all, and drcovlib here is simply writing to a file
 * anyway, more like an end tool than a library that returns raw coverage data.
 * However, making this a library makes it easier to share parsing code for
 * postprocessing tools and makes it easier to export the module table in the
 * future.  Other factors into the decision are whether large tools like
 * Dr. Memory want to use a shared library model, which is required for 2
 * clients and which complicates deployment.  Since Dr. Memory has its own
 * frontend, even a 2-client model still requires special-case support inside
 * the Dr. Memory code base.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h" // drMultiCov - include drreg
#include "drx.h"
#include "drcovlib.h"
#include "hashtable.h"
#include "drtable.h" // Edge coverage - remove unnecessary modules.h include
#include "drcovlib_private.h"
#include <limits.h>
#include <string.h>

// Edge coverage - includes for hashing and constants
#include <stdint.h>
#define XXH_INLINE_ALL
#include "xxhash.h"
#undef XXH_INLINE_ALL
#define EDGE_COVERAGE_MAP_SIZE 65536

#define UNKNOWN_MODULE_ID USHRT_MAX

/* This is not exposed: internal use only */
uint verbose;

#define OPTION_MAX_LENGTH MAXIMUM_PATH

static drcovlib_options_t options;
static char logdir[MAXIMUM_PATH];

typedef struct _per_thread_t {
    void *bb_table;
    file_t log;
    char logname[MAXIMUM_PATH];
} per_thread_t;

static per_thread_t *global_data;
static bool drcov_per_thread = false;
#ifndef WINDOWS
static int sysnum_execve = IF_X64_ELSE(59, 11);
#endif
static volatile bool go_native;
static int tls_idx = -1;
static int drcovlib_init_count;

// Edge coverage - new globals
static const char *target_module;
static unsigned char *edge_coverage_area;
static int edge_coverage_tls = -1;

// Edge coverage - add inline hash function
static inline uint64_t
hash64(uint8_t *key, uint32_t len)
{
    return XXH3_64bits(key, len);
}

/****************************************************************************
 * Utility Functions
 */
static file_t
log_file_create_helper(void *drcontext, const char *suffix, char *buf, size_t buf_els)
{
    file_t log = drx_open_unique_appid_file(
        options.logdir,
        drcontext == NULL ? dr_get_process_id() : dr_get_thread_id(drcontext),
        options.logprefix, suffix,
#ifndef WINDOWS
        DR_FILE_CLOSE_ON_FORK |
#endif
            DR_FILE_ALLOW_LARGE,
        buf, buf_els);
    if (log != INVALID_FILE) {
        dr_log(drcontext, DR_LOG_ALL, 1, "drcov: log file is %s\n", buf);
        NOTIFY(1, "<created log file %s>\n", buf);
    }
    return log;
}

static void
log_file_create(void *drcontext, per_thread_t *data)
{
    data->log =
        log_file_create_helper(drcontext, drcontext == NULL ? "proc.log" : "thd.log",
                               data->logname, BUFFER_SIZE_ELEMENTS(data->logname));
}

/****************************************************************************
 * BB Table Functions
 */

static bool
bb_table_entry_print(ptr_uint_t idx, void *entry, void *iter_data)
{
    per_thread_t *data = iter_data;
    bb_entry_t *bb_entry = (bb_entry_t *)entry;
    if (bb_entry->hits_since_last_reset != 0) // drMultiCov - add if statement
    {
        dr_fprintf(data->log, "module[%3u]: " PFX ", %3u", bb_entry->mod_id, bb_entry->start,
                   bb_entry->size);
        dr_fprintf(data->log, "\n");
    }
    return true; /* continue iteration */
}

static void
bb_table_print(void *drcontext, per_thread_t *data)
{
    ASSERT(data != NULL, "data must not be NULL");
    if (data->log == INVALID_FILE) {
        ASSERT(false, "invalid log file");
        return;
    }
    dr_fprintf(data->log, "BB Table: %u bbs\n", drtable_num_entries(data->bb_table));
    if (TEST(DRCOVLIB_DUMP_AS_TEXT, options.flags)) {
        dr_fprintf(data->log, "module id, start, size:\n");
        drtable_iterate(data->bb_table, data, bb_table_entry_print);
    } else
        drtable_dump_entries(data->bb_table, data->log);
}

static bb_entry_t * // drMultiCov - change return type
bb_table_entry_add(void *drcontext, per_thread_t *data, app_pc start, uint size)
{
    bb_entry_t *bb_entry = drtable_alloc(data->bb_table, 1, NULL);
    uint mod_id;
    app_pc mod_start;
    drcovlib_status_t res = drmodtrack_lookup(drcontext, start, &mod_id, &mod_start);
    /* we do not de-duplicate repeated bbs */
    ASSERT(size < USHRT_MAX, "size overflow");
    bb_entry->size = (ushort)size;
    bb_entry->hits_since_last_reset = 0; // drMultiCov - initialize to 0
    if (res == DRCOVLIB_SUCCESS) {
        ASSERT(mod_id < USHRT_MAX, "module id overflow");
        bb_entry->mod_id = (ushort)mod_id;
        ASSERT(start > mod_start, "wrong module");
        bb_entry->start = (uint)(start - mod_start);
    } else {
        /* XXX: we just truncate the address, which may have wrong value
         * in x64 arch. It should be ok now since it is an unknown module,
         * which will be ignored in the post-processing.
         * Should be handled for JIT code in the future.
         */
        bb_entry->mod_id = UNKNOWN_MODULE_ID;
        bb_entry->start = (uint)(ptr_uint_t)start;
    }
    return bb_entry; // drMultiCov - return pointer to the newly allocated entry
}

#define INIT_BB_TABLE_ENTRIES 4096
static void *
bb_table_create(bool synch)
{
    return drtable_create(INIT_BB_TABLE_ENTRIES, sizeof(bb_entry_t), 0 /* flags */, synch,
                          NULL);
}

static void
bb_table_destroy(void *table, void *data)
{
    drtable_destroy(table, data);
}

static void
version_print(file_t log)
{
    if (log == INVALID_FILE) {
        /* It is possible that failure on log file creation is caused by the
         * running process not having enough privilege, so this is not a
         * release-build fatal error
         */
        ASSERT(false, "invalid log file");
        return;
    }
    dr_fprintf(log, "DRCOV VERSION: %d\n", DRCOV_VERSION);
    dr_fprintf(log, "DRCOV FLAVOR: %s\n", DRCOV_FLAVOR);
}

static void
dump_drcov_data(void *drcontext, per_thread_t *data)
{
    if (data->log == INVALID_FILE) {
        /* It is possible that failure on log file creation is caused by the
         * running process not having enough privilege, so this is not a
         * release-build fatal error
         */
        ASSERT(false, "invalid log file");
        return;
    }
    version_print(data->log);

    // Edge coverage - print hash to log
    uint64_t hash = hash64(edge_coverage_area, EDGE_COVERAGE_MAP_SIZE);
    dr_fprintf(data->log, "Edge Coverage Hash: %lx\n", hash);

    drmodtrack_dump(data->log);
    bb_table_print(drcontext, data);
}

/****************************************************************************
 * Thread/Global Data Creation/Destroy
 */

/* make a copy of global data for pre-thread cache */
static per_thread_t *
thread_data_copy(void *drcontext)
{
    per_thread_t *data;
    ASSERT(drcontext != NULL, "drcontext must not be NULL");
    data = dr_thread_alloc(drcontext, sizeof(*data));
    *data = *global_data;
    return data;
}

static per_thread_t *
thread_data_create(void *drcontext)
{
    per_thread_t *data;
    if (drcontext == NULL) {
        ASSERT(!drcov_per_thread, "drcov_per_thread should not be set");
        data = dr_global_alloc(sizeof(*data));
    } else {
        ASSERT(drcov_per_thread, "drcov_per_thread should be set");
        data = dr_thread_alloc(drcontext, sizeof(*data));
    }
    /* XXX: can we assume bb create event is serialized,
     * if so, no lock is required for bb_table operation.
     */
    data->bb_table = bb_table_create(drcontext == NULL ? true : false);
    log_file_create(drcontext, data);
    return data;
}

static void
thread_data_destroy(void *drcontext, per_thread_t *data)
{
    /* destroy the bb table */
    bb_table_destroy(data->bb_table, data);
    dr_close_file(data->log);
    /* free thread data */
    if (drcontext == NULL) {
        ASSERT(!drcov_per_thread, "drcov_per_thread should not be set");
        dr_global_free(data, sizeof(*data));
    } else {
        ASSERT(drcov_per_thread, "drcov_per_thread is not set");
        dr_thread_free(drcontext, data, sizeof(*data));
    }
}

static void *
global_data_create(void)
{
    return thread_data_create(NULL);
}

static void
global_data_destroy(per_thread_t *data)
{
    thread_data_destroy(NULL, data);
}

/****************************************************************************
 * Event Callbacks
 */

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
#ifdef WINDOWS
    return false;
#else
    return sysnum == sysnum_execve;
#endif
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
#ifdef UNIX
    if (sysnum == sysnum_execve) {
        /* for !drcov_per_thread, the per-thread data is a copy of global data */
        per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        ASSERT(data != NULL, "data must not be NULL");
        if (!drcov_per_thread)
            drcontext = NULL;
        /* We only dump the data but do not free any memory.
         * XXX: for drcov_per_thread, we only dump the current thread.
         */
        dump_drcov_data(drcontext, data);
        /* TODO: add execve test.
         * i#1390-c#8: iterate over all the other threads using DR API and dump data.
         * i#1390-c#9: update drcov2lcov to handle multiple dumps in the same file.
         */
    }
#endif
    return true;
}

/* We collect the basic block information including offset from module base,
 * size, and num of instructions, and add it into a basic block table without
 * instrumentation.
 */
static dr_emit_flags_t
event_basic_block_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                           bool translating, OUT void **user_data)
{
    per_thread_t *data;
    instr_t *instr;
    app_pc tag_pc, start_pc, end_pc;

    /* do nothing for translation */
    if (translating)
        return DR_EMIT_DEFAULT;

    data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    /* Collect the number of instructions and the basic block size,
     * assuming the basic block does not have any elision on control
     * transfer instructions, which is true for default options passed
     * to DR but not for -opt_speed.
     */
    /* We separate the tag from the instr pc ranges to handle displaced code
     * such as for the vsyscall hook.
     */
    tag_pc = dr_fragment_app_pc(tag);
    start_pc = instr_get_app_pc(instrlist_first_app(bb));
    end_pc = start_pc; /* for finding the size */
    for (instr = instrlist_first_app(bb); instr != NULL;
         instr = instr_get_next_app(instr)) {
        app_pc pc = instr_get_app_pc(instr);
        int len = instr_length(drcontext, instr);
        /* -opt_speed (elision) is not supported */
        /* For rep str expansion pc may be one back from start pc but equal to the tag. */
        ASSERT(pc != NULL && (pc >= start_pc || pc == tag_pc),
               "-opt_speed is not supported");
        if (pc + len > end_pc)
            end_pc = pc + len;
    }
    /* We allow duplicated basic blocks for the following reasons:
     * 1. Avoids handling issues like code cache consistency, e.g.,
     *    module load/unload, self-modifying code, etc.
     * 2. Avoids the overhead on duplication check.
     * 3. Stores more information on code cache events, e.g., trace building,
     *    repeated bb building, etc.
     * 4. The duplication can be easily handled in a post-processing step,
     *    which is required anyway.
     */
    *user_data = (void *)bb_table_entry_add(drcontext, data, tag_pc, (uint)(end_pc - start_pc)); // drMultiCov - set user_data

    if (go_native)
        return DR_EMIT_GO_NATIVE;
    else
        return DR_EMIT_DEFAULT;
}

// drMultiCov - new function
// Inspired by https://github.com/firodj/bbtrace/blob/master/clients/bbtrace.c, http://dynamorio.org/docs/samples/bbcount.c, and https://github.com/googleprojectzero/winafl/blob/master/winafl.c
static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                bool for_trace, bool translating, void *user_data)
{
    if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;

    // Needed to ensure instrumention unconditionally executes
    drmgr_disable_auto_predication(drcontext, bb);

#if defined(AARCH64) || defined(ARM)
    // Initialization
    size_t naked_addr;
    reg_id_t reg1, reg2;
    opnd_t opnd1, opnd2, opnd3;
    instr_t *new_instr;

    // Save registers
    drreg_reserve_aflags(drcontext, bb, inst);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg1);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg2);

    // Get address to increment
    naked_addr = (size_t) & (((bb_entry_t *)user_data)->hits_since_last_reset);

#if defined(ARM)
    // Load high
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_INT16(naked_addr & 0xFFFF);
    new_instr = INSTR_CREATE_movw(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // Load low
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_INT16((naked_addr >> 16) & 0xFFFF);
    new_instr = INSTR_CREATE_movt(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);
#else
    // Load
    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_INT16((naked_addr >> 0) & 0xFFFF);
    opnd3 = OPND_CREATE_INT8(0);
    new_instr = INSTR_CREATE_movk(drcontext, opnd1, opnd2, opnd3);
    instrlist_meta_preinsert(bb, inst, new_instr);

    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_INT16((naked_addr >> 16) & 0xFFFF);
    opnd3 = OPND_CREATE_INT8(16);
    new_instr = INSTR_CREATE_movk(drcontext, opnd1, opnd2, opnd3);
    instrlist_meta_preinsert(bb, inst, new_instr);

    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_INT16((naked_addr >> 32) & 0xFFFF);
    opnd3 = OPND_CREATE_INT8(32);
    new_instr = INSTR_CREATE_movk(drcontext, opnd1, opnd2, opnd3);
    instrlist_meta_preinsert(bb, inst, new_instr);

    opnd1 = opnd_create_reg(reg1);
    opnd2 = OPND_CREATE_INT16((naked_addr >> 48) & 0xFFFF);
    opnd3 = OPND_CREATE_INT8(48);
    new_instr = INSTR_CREATE_movk(drcontext, opnd1, opnd2, opnd3);
    instrlist_meta_preinsert(bb, inst, new_instr);
#endif
    // Dereference
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_MEM32(reg1, 0);
    new_instr = INSTR_CREATE_ldr(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // Increment
    opnd1 = opnd_create_reg(reg2);
    opnd2 = opnd_create_reg(reg2);
    opnd3 = OPND_CREATE_INT(1));
    new_instr = INSTR_CREATE_add(drcontext, opnd1, opnd2, opnd3);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // Store
    opnd1 = OPND_CREATE_MEM32(reg1, 0);
    opnd2 = opnd_create_reg(reg2);
    new_instr = INSTR_CREATE_str(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // Restore registers
    drreg_unreserve_register(drcontext, bb, inst, reg2);
    drreg_unreserve_register(drcontext, bb, inst, reg1);
    drreg_unreserve_aflags(drcontext, bb, inst);

#else
    // Initialization
    bool edge_coverage;
    app_pc start_pc, mod_start;
    module_entry_t *mod_entry;
    uint mod_id, offset;
    const char *mod_name;
    reg_id_t reg, reg2, reg3;
    opnd_t opnd1, opnd2;
    instr_t *new_instr;

    // Check module name
    edge_coverage = false;
    start_pc = dr_fragment_app_pc(tag);
    drcovlib_status_t res = drmodtrack_lookup_data(drcontext, start_pc, &mod_id, &mod_start, &mod_entry);
    if (res == DRCOVLIB_SUCCESS)
    {
        mod_name = dr_module_preferred_name(mod_entry->data);
        if (strcasecmp(mod_name, target_module) == 0)
        {
            edge_coverage = true;
        }
    }

    // Reserve registers
    drreg_reserve_aflags(drcontext, bb, inst);
    if (edge_coverage)
    {
        drreg_reserve_register(drcontext, bb, inst, NULL, &reg);
        drreg_reserve_register(drcontext, bb, inst, NULL, &reg2);
        drreg_reserve_register(drcontext, bb, inst, NULL, &reg3);

        // Get BB offset
        offset = (uint)(start_pc - mod_start);
        offset &= EDGE_COVERAGE_MAP_SIZE - 1;

        // Load pointer to previous offset into reg3
        drmgr_insert_read_tls_field(drcontext, edge_coverage_tls, bb, inst, reg3);

        // Load pointer to shared memory into reg2
        opnd1 = opnd_create_reg(reg2);
        opnd2 = OPND_CREATE_INTPTR((uint64)edge_coverage_area);
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
        offset = (offset >> 1) & (EDGE_COVERAGE_MAP_SIZE - 1);
        opnd1 = OPND_CREATE_MEMPTR(reg3, 0);
        opnd2 = OPND_CREATE_INT32(offset);
        new_instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
        instrlist_meta_preinsert(bb, inst, new_instr);
    }

    // Increment for drMultiCov
    opnd1 = OPND_CREATE_ABSMEM(&(((bb_entry_t *)user_data)->hits_since_last_reset), OPSZ_4);
    new_instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // Unreserve registers
    if (edge_coverage)
    {
        drreg_unreserve_register(drcontext, bb, inst, reg3);
        drreg_unreserve_register(drcontext, bb, inst, reg2);
        drreg_unreserve_register(drcontext, bb, inst, reg);
    }
    drreg_unreserve_aflags(drcontext, bb, inst);

#endif

    return DR_EMIT_DEFAULT;
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data;

    data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    ASSERT(data != NULL, "data must not be NULL");

    if (drcov_per_thread) {
        dump_drcov_data(drcontext, data);
        thread_data_destroy(drcontext, data);
    } else {
        /* the per-thread data is a copy of global data */
        dr_thread_free(drcontext, data, sizeof(*data));
    }

    // Edge coverage - free TLS field
    void *thread_data = drmgr_get_tls_field(drcontext, edge_coverage_tls);
    dr_thread_free(drcontext, thread_data, 2 * sizeof(void *));
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data;
    static volatile int thread_count;

    if (options.native_until_thread > 0) {
        int local_count = dr_atomic_add32_return_sum(&thread_count, 1);
        NOTIFY(1, "@@@@@@@@@@@@@ new thread #%d " TIDFMT "\n", local_count,
               dr_get_thread_id(drcontext));
        if (go_native && local_count == options.native_until_thread) {
            void **drcontexts = NULL;
            uint num_threads, i;
            go_native = false;
            NOTIFY(1, "thread " TIDFMT " suspending all threads\n",
                   dr_get_thread_id(drcontext));
            if (dr_suspend_all_other_threads_ex(&drcontexts, &num_threads, NULL,
                                                DR_SUSPEND_NATIVE)) {
                NOTIFY(1, "suspended %d threads\n", num_threads);
                for (i = 0; i < num_threads; i++) {
                    if (dr_is_thread_native(drcontexts[i])) {
                        NOTIFY(2, "\txxx taking over thread #%d " TIDFMT "\n", i,
                               dr_get_thread_id(drcontexts[i]));
                        dr_retakeover_suspended_native_thread(drcontexts[i]);
                    } else {
                        NOTIFY(2, "\tthread #%d " TIDFMT " under DR\n", i,
                               dr_get_thread_id(drcontexts[i]));
                    }
                }
                if (!dr_resume_all_other_threads(drcontexts, num_threads)) {
                    ASSERT(false, "failed to resume threads");
                }
            } else {
                ASSERT(false, "failed to suspend threads");
            }
        }
    }
    /* allocate thread private data for per-thread cache */
    if (drcov_per_thread)
        data = thread_data_create(drcontext);
    else
        data = thread_data_copy(drcontext);
    drmgr_set_tls_field(drcontext, tls_idx, data);

    // Edge coverage - allocate TLS field
    void **thread_data = (void **)dr_thread_alloc(drcontext, sizeof(void *));
    *thread_data = 0;
    drmgr_set_tls_field(drcontext, edge_coverage_tls, thread_data);
}

#ifndef WINDOWS
static void
event_fork(void *drcontext)
{
    if (!drcov_per_thread) {
        log_file_create(NULL, global_data);
    } else {
        per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
        if (data != NULL) {
            thread_data_destroy(drcontext, data);
        }
        event_thread_init(drcontext);
    }
}
#endif

drcovlib_status_t
drcovlib_logfile(void *drcontext, OUT const char **path)
{
    if (path == NULL)
        return DRCOVLIB_ERROR_INVALID_PARAMETER;
    if (drcontext != NULL) {
        per_thread_t *data;
        if (!drcov_per_thread)
            return DRCOVLIB_ERROR_INVALID_PARAMETER;
        data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        ASSERT(data != NULL, "data must not be NULL");
        *path = data->logname;
    } else {
        if (drcov_per_thread)
            return DRCOVLIB_ERROR_INVALID_PARAMETER;
        *path = global_data->logname;
    }
    return DRCOVLIB_SUCCESS;
}

drcovlib_status_t
drcovlib_dump(void *drcontext)
{
    if (drcontext != NULL) {
        per_thread_t *data;
        if (!drcov_per_thread)
            return DRCOVLIB_ERROR_INVALID_PARAMETER;
        data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        ASSERT(data != NULL, "data must not be NULL");
        dump_drcov_data(drcontext, data);
    } else {
        if (drcov_per_thread)
            return DRCOVLIB_ERROR_INVALID_PARAMETER;
        dump_drcov_data(drcontext, global_data);
    }
    return DRCOVLIB_SUCCESS;
}

drcovlib_status_t
drcovlib_exit(void)
{
    int count = dr_atomic_add32_return_sum(&drcovlib_init_count, -1);
    if (count != 0)
        return DRCOVLIB_SUCCESS;

    if (!drcov_per_thread) {
        dump_drcov_data(NULL, global_data);
        global_data_destroy(global_data);
    }
    /* destroy module table */
    drmodtrack_exit();

    drmgr_unregister_tls_field(tls_idx);

    // Edge coverage - free resources
    drmgr_unregister_tls_field(edge_coverage_tls);
    dr_global_free(edge_coverage_area, EDGE_COVERAGE_MAP_SIZE);
    drreg_exit();

    drx_exit();
    drmgr_exit();

    return DRCOVLIB_SUCCESS;
}

static drcovlib_status_t
event_init(void)
{
    drcovlib_status_t res;
    uint64 max_elide_jmp = 0;
    uint64 max_elide_call = 0;
    /* assuming no elision */
    if (!dr_get_integer_option("max_elide_jmp", &max_elide_jmp) ||
        !dr_get_integer_option("max_elide_call", &max_elide_jmp) || max_elide_jmp != 0 ||
        max_elide_call != 0)
        return DRCOVLIB_ERROR_INVALID_SETUP;

    /* create module table */
    res = drmodtrack_init();
    if (res != DRCOVLIB_SUCCESS)
        return res;

    /* create process data if whole process bb coverage. */
    if (!drcov_per_thread)
        global_data = global_data_create();
    return DRCOVLIB_SUCCESS;
}

drcovlib_status_t
drcovlib_init(drcovlib_options_t *ops)
{
    int count = dr_atomic_add32_return_sum(&drcovlib_init_count, 1);
    if (count > 1)
        return DRCOVLIB_SUCCESS;

    if (ops->struct_size != sizeof(options))
        return DRCOVLIB_ERROR_INVALID_PARAMETER;
    if ((ops->flags & (~(DRCOVLIB_DUMP_AS_TEXT | DRCOVLIB_THREAD_PRIVATE))) != 0)
        return DRCOVLIB_ERROR_INVALID_PARAMETER;
    if (TEST(DRCOVLIB_THREAD_PRIVATE, ops->flags)) {
        if (!dr_using_all_private_caches())
            return DRCOVLIB_ERROR_INVALID_SETUP;
        drcov_per_thread = true;
    }
    options = *ops;
    if (options.logdir != NULL)
        dr_snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s", ops->logdir);
    else /* default */
        dr_snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), ".");
    NULL_TERMINATE_BUFFER(logdir);
    options.logdir = logdir;
    if (options.logprefix == NULL)
        options.logprefix = "drcov";
    if (options.native_until_thread > 0)
        go_native = true;

    drmgr_init();
    drx_init();

    // Edge coverage - drreg initialization
    drreg_options_t drreg_ops = {sizeof(drreg_ops), 2 /*max slots needed: aflags*/, false};
    drreg_init(&drreg_ops);

    // Edge coverage - TLS initialization
    edge_coverage_tls = drmgr_register_tls_field();
    if (edge_coverage_tls == -1)
        return DRCOVLIB_ERROR;
    
    // Edge coverage - global area initialization
    edge_coverage_area = (unsigned char *)dr_global_alloc(EDGE_COVERAGE_MAP_SIZE);
    memset(edge_coverage_area, 0, EDGE_COVERAGE_MAP_SIZE);

    // Edge coverage - set target module
    target_module = ops->target_module;

    /* We follow a simple model of the caller requesting the coverage dump,
     * either via calling the exit routine, using its own soft_kills nudge, or
     * an explicit dump call for unusual cases.  This means that drx's
     * soft_kills remains inside the outer later, i.e., the drcov client.  This
     * is the easiest approach for coordinating soft_kills among many libraries.
     * Thus, we do *not* register for an exit event here.
     */

    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    drmgr_register_bb_instrumentation_event(event_basic_block_analysis, event_bb_insert, NULL); // drMultiCov - add instrumentation function
    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
#ifdef UNIX
    dr_register_fork_init_event(event_fork);
#endif

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1)
        return DRCOVLIB_ERROR;

    return event_init();
}

// drMultiCov - new function
static bool
bb_table_entry_clear_hits(ptr_uint_t idx, void *entry, void *iter_data)
{
    bb_entry_t *bb_entry = (bb_entry_t *)entry;
    bb_entry->hits_since_last_reset = 0;

    return true;
}

// drMultiCov - new function
drcovlib_status_t
reset_coverage(void)
{
    void **drcontexts = NULL;
    uint num_threads, i;
    if (dr_suspend_all_other_threads_ex(&drcontexts, &num_threads, NULL, DR_SUSPEND_NATIVE))
    {
        NOTIFY(1, "suspended %d threads\n", num_threads);
        if (!drcov_per_thread)
        {
            drtable_iterate(global_data->bb_table, global_data, bb_table_entry_clear_hits);
        }
        else
        {
            for (i = 0; i < num_threads; i++)
            {
                per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontexts[i], tls_idx);
                drtable_iterate(data->bb_table, data, bb_table_entry_clear_hits);
            }
        }
        if (!dr_resume_all_other_threads(drcontexts, num_threads))
        {
            ASSERT(false, "failed to resume threads");
        }
    }
    else
    {
        ASSERT(false, "failed to suspend threads");
    }

    return DRCOVLIB_SUCCESS;
}

// drMultiCov - new function
drcovlib_status_t
dump_current_coverage(void)
{
    void **drcontexts = NULL;
    uint num_threads, i;
    if (dr_suspend_all_other_threads_ex(&drcontexts, &num_threads, NULL, DR_SUSPEND_NATIVE))
    {
        NOTIFY(1, "suspended %d threads\n", num_threads);
        if (!drcov_per_thread)
        {
            dump_drcov_data(NULL, global_data);
            dr_close_file(global_data->log);
            log_file_create(NULL, global_data);
        }
        else
        {
            for (i = 0; i < num_threads; i++)
            {
                per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontexts[i], tls_idx);
                dump_drcov_data(drcontexts[i], data);
                dr_close_file(data->log);
                log_file_create(drcontexts[i], data);
            }
        }
        if (!dr_resume_all_other_threads(drcontexts, num_threads))
        {
            ASSERT(false, "failed to resume threads");
        }
    }
    else
    {
        ASSERT(false, "failed to suspend threads");
    }

    return DRCOVLIB_SUCCESS;
}
