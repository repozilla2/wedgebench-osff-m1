/*
 * parser_target.c — Sentinel OSFF M1 Reference UART-style Parser
 *
 * This is a INTENTIONALLY MIXED implementation:
 *   - parser_safe_*  : hardened versions (correct behavior)
 *   - parser_vuln_*  : vulnerable versions with known wedge/crash paths
 *
 * The fuzzer targets both. Safe variants should produce zero wedges.
 * Vulnerable variants demonstrate detectable wedge conditions.
 *
 * Frame format:
 *   [SOF: 0xAA] [LEN: 1 byte] [PAYLOAD: LEN bytes] [CHK: 1 byte XOR]
 *
 * Constants (must match wedge_definition.md):
 *   MAX_FRAME_SIZE     256
 *   PARSER_MAX_ITERS   512
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ─── Public constants ─────────────────────────────────────────────────── */
#define SOF_BYTE           0xAA
#define MAX_FRAME_SIZE     256
#define MAX_PAYLOAD_SIZE   (MAX_FRAME_SIZE - 3)   /* SOF + LEN + CHK */
#define PARSER_MAX_ITERS   512

/* ─── Progress instrumentation (harness reads this) ────────────────────── */
volatile size_t g_parser_bytes_consumed = 0;

/* ─── Parser states ─────────────────────────────────────────────────────── */
typedef enum {
    STATE_IDLE      = 0,
    STATE_LEN       = 1,
    STATE_PAYLOAD   = 2,
    STATE_CHECKSUM  = 3
} ParserState;

/* ─── Parser context ────────────────────────────────────────────────────── */
typedef struct {
    ParserState state;
    uint8_t     expected_len;
    uint8_t     payload[MAX_PAYLOAD_SIZE];
    uint8_t     payload_idx;
    uint8_t     running_xor;
    size_t      frames_accepted;
    size_t      frames_rejected;
} ParserCtx;

/* ─── Result type ───────────────────────────────────────────────────────── */
typedef enum {
    PARSE_CONTINUE  = 0,   /* need more bytes */
    PARSE_ACCEPT    = 1,   /* complete valid frame */
    PARSE_REJECT    = 2,   /* malformed, returned to IDLE */
    PARSE_ERROR     = -1   /* internal error */
} ParseResult;

/* ══════════════════════════════════════════════════════════════════════════
 * SAFE PARSER — hardened, bounded, no wedge paths
 * ══════════════════════════════════════════════════════════════════════════ */

void parser_safe_init(ParserCtx *ctx) {
    memset(ctx, 0, sizeof(ParserCtx));
    ctx->state = STATE_IDLE;
}

/*
 * parser_safe_feed — feed one byte to the safe parser.
 * Returns PARSE_ACCEPT on complete valid frame,
 *         PARSE_REJECT on malformed input (resets to IDLE),
 *         PARSE_CONTINUE otherwise.
 *
 * All loops are bounded. No dynamic allocation. No recursion.
 */
ParseResult parser_safe_feed(ParserCtx *ctx, uint8_t byte) {
    g_parser_bytes_consumed++;

    switch (ctx->state) {
        case STATE_IDLE:
            if (byte == SOF_BYTE) {
                ctx->state       = STATE_LEN;
                ctx->running_xor = SOF_BYTE;
            }
            /* Non-SOF bytes in IDLE are silently discarded — not a reject */
            return PARSE_CONTINUE;

        case STATE_LEN:
            /* Enforce max payload length — reject overlong before allocating */
            if (byte == 0 || byte > MAX_PAYLOAD_SIZE) {
                parser_safe_init(ctx);
                ctx->frames_rejected++;
                return PARSE_REJECT;
            }
            ctx->expected_len  = byte;
            ctx->payload_idx   = 0;
            ctx->running_xor  ^= byte;
            ctx->state         = STATE_PAYLOAD;
            return PARSE_CONTINUE;

        case STATE_PAYLOAD:
            /* Bounds-checked payload accumulation */
            if (ctx->payload_idx >= MAX_PAYLOAD_SIZE) {
                /* Should not happen given LEN check, but defensive */
                parser_safe_init(ctx);
                ctx->frames_rejected++;
                return PARSE_REJECT;
            }
            ctx->payload[ctx->payload_idx++] = byte;
            ctx->running_xor ^= byte;
            if (ctx->payload_idx == ctx->expected_len) {
                ctx->state = STATE_CHECKSUM;
            }
            return PARSE_CONTINUE;

        case STATE_CHECKSUM:
            if (byte != ctx->running_xor) {
                parser_safe_init(ctx);
                ctx->frames_rejected++;
                return PARSE_REJECT;
            }
            ctx->frames_accepted++;
            parser_safe_init(ctx);   /* reset for next frame */
            return PARSE_ACCEPT;

        default:
            /* Unreachable — defensive reset */
            parser_safe_init(ctx);
            return PARSE_ERROR;
    }
}

/*
 * parser_safe_feed_buffer — feed a buffer, return count of accepted frames.
 * Bounded by PARSER_MAX_ITERS as a secondary safety guard.
 */
int parser_safe_feed_buffer(ParserCtx *ctx, const uint8_t *buf, size_t len) {
    int accepted = 0;
    size_t iters = 0;
    for (size_t i = 0; i < len && iters < PARSER_MAX_ITERS; i++, iters++) {
        ParseResult r = parser_safe_feed(ctx, buf[i]);
        if (r == PARSE_ACCEPT) accepted++;
    }
    return accepted;
}

/* ══════════════════════════════════════════════════════════════════════════
 * VULNERABLE PARSER — intentional wedge/crash paths for fuzz demonstration
 * ══════════════════════════════════════════════════════════════════════════ */

void parser_vuln_init(ParserCtx *ctx) {
    memset(ctx, 0, sizeof(ParserCtx));
    ctx->state = STATE_IDLE;
}

/*
 * parser_vuln_feed_buffer — VULNERABLE version.
 *
 * Intentional defects (all present and detectable via per_case_results):
 *   1. No LEN upper-bound check → overlong frame causes out-of-bounds write
 *   2. Unbounded inner search loop for SOF → no iter guard
 *   3. No outer loop iter guard
 *   4. Zero-length frame acceptance: vuln accepts zero-length frames that safe
 *      correctly rejects. Observable as frames_accepted divergence on
 *      zero_length_valid_chk corpus case (safe=0, vuln=1).
 */
int parser_vuln_feed_buffer(ParserCtx *ctx, const uint8_t *buf, size_t len) {
    int accepted = 0;

    for (size_t i = 0; i < len; i++) {
        uint8_t byte = buf[i];
        g_parser_bytes_consumed++;

        switch (ctx->state) {
            case STATE_IDLE:
                /* VULN: unbounded search — will spin on non-SOF garbage */
                while (i < len && buf[i] != SOF_BYTE) {
                    i++;
                    /* no g_parser_bytes_consumed increment here — 
                       no-progress wedge detectable by harness */
                }
                if (i < len) {
                    ctx->state       = STATE_LEN;
                    ctx->running_xor = SOF_BYTE;
                }
                break;

            case STATE_LEN:
                /* VULN: no upper bound check — LEN=255 → huge payload */
                ctx->expected_len = byte;
                ctx->payload_idx  = 0;
                ctx->running_xor ^= byte;
                if (byte == 0) {
                    /* VULN: zero-length accepted, goes to CHECKSUM immediately */
                    ctx->state = STATE_CHECKSUM;
                } else {
                    ctx->state = STATE_PAYLOAD;
                }
                break;

            case STATE_PAYLOAD:
                /* VULN: no bounds check on payload_idx */
                ctx->payload[ctx->payload_idx++] = byte;  /* potential OOB write */
                ctx->running_xor ^= byte;
                if (ctx->payload_idx == ctx->expected_len) {
                    ctx->state = STATE_CHECKSUM;
                }
                break;

            case STATE_CHECKSUM:
                if (byte == ctx->running_xor) {
                    ctx->frames_accepted++;
                    accepted++;
                } else {
                    ctx->frames_rejected++;
                }
                parser_vuln_init(ctx);
                break;

            default:
                break;
        }
    }
    return accepted;
}
