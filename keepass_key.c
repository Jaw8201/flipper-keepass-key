/**
 * @file keepass_key.c
 * @brief Shareable first-run setup demo for KeePass Key on Flipper Zero.
 *
 * Current functionality:
 *   - First-run creation of a private directional unlock sequence.
 *   - Sequence confirmation before saving.
 *   - Variable sequence length (8-32 directions).
 *   - Persistent sequence storage in app data (never compiled into source).
 *   - Full-sequence validation without revealing the first wrong position.
 *   - Persistent progressive failed-attempt protection.
 *   - 30-second temporary authorization window.
 *   - RFC 2202 HMAC-SHA1 self-test.
 *   - Per-installation 160-bit HMAC key generation.
 *   - Separate persistent HMAC credential storage.
 *   - Provisioning migration for existing demo installations.
 *
 * SECURITY NOTE:
 * This is still development software. The saved directional sequence is local
 * authorization data, not the future KeePass cryptographic key. Do not use this
 * build as the sole protection for a production KeePass database.
 */

#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>
#include <furi_hal_random.h>

#define MIN_SEQUENCE_LENGTH 8U
#define MAX_SEQUENCE_LENGTH 32U
#define AUTH_TIMEOUT_MS 30000U

#define STATE_DIR EXT_PATH("apps_data/keepass_key")
#define STATE_PATH EXT_PATH("apps_data/keepass_key/state.bin")
#define STATE_VERSION 2U

#define KEY_PATH EXT_PATH("apps_data/keepass_key/hmac_key.bin")
#define KEY_VERSION 1U
#define HMAC_KEY_SIZE 20U

typedef enum {
    AppModeSetupCreate,
    AppModeSetupConfirm,
    AppModeLocked,
    AppModeIncorrect,
    AppModeAuthorized,
} AppMode;

typedef struct {
    uint8_t version;
    uint8_t failures;
    uint8_t sequence_length;
    uint8_t sequence[MAX_SEQUENCE_LENGTH];
} KeePassPersistentState;

/* --------------------------------------------------------------------------
 * SHA-1 / HMAC-SHA1 Development Self-Test
 * -------------------------------------------------------------------------- */

/**
 * This implementation exists to establish a deterministic cryptographic
 * checkpoint before host communication and real key provisioning are added.
 *
 * IMPORTANT:
 * The key and challenge below are PUBLIC RFC 2202 test-vector values.
 * They are not credentials and MUST NOT be replaced with a real KeePass key
 * in source control.
 */

#define SHA1_BLOCK_SIZE 64U
#define SHA1_DIGEST_SIZE 20U

typedef struct {
    uint32_t state[5];
    uint64_t bit_count;
    uint8_t buffer[SHA1_BLOCK_SIZE];
    size_t buffer_length;
} Sha1Context;

static uint32_t sha1_rotl(uint32_t value, uint8_t bits) {
    return (value << bits) | (value >> (32U - bits));
}

static void sha1_transform(Sha1Context* ctx, const uint8_t block[SHA1_BLOCK_SIZE]) {
    uint32_t w[80];

    for(uint8_t i = 0U; i < 16U; i++) {
        const uint8_t j = (uint8_t)(i * 4U);
        w[i] = ((uint32_t)block[j] << 24U) |
               ((uint32_t)block[j + 1U] << 16U) |
               ((uint32_t)block[j + 2U] << 8U) |
               ((uint32_t)block[j + 3U]);
    }

    for(uint8_t i = 16U; i < 80U; i++) {
        w[i] = sha1_rotl(
            w[i - 3U] ^ w[i - 8U] ^ w[i - 14U] ^ w[i - 16U],
            1U);
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];

    for(uint8_t i = 0U; i < 80U; i++) {
        uint32_t f;
        uint32_t k;

        if(i < 20U) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999UL;
        } else if(i < 40U) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1UL;
        } else if(i < 60U) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCUL;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6UL;
        }

        const uint32_t temp =
            sha1_rotl(a, 5U) + f + e + k + w[i];

        e = d;
        d = c;
        c = sha1_rotl(b, 30U);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_init(Sha1Context* ctx) {
    ctx->state[0] = 0x67452301UL;
    ctx->state[1] = 0xEFCDAB89UL;
    ctx->state[2] = 0x98BADCFEUL;
    ctx->state[3] = 0x10325476UL;
    ctx->state[4] = 0xC3D2E1F0UL;
    ctx->bit_count = 0U;
    ctx->buffer_length = 0U;
}

static void sha1_update(Sha1Context* ctx, const uint8_t* data, size_t length) {
    ctx->bit_count += ((uint64_t)length * 8ULL);

    while(length > 0U) {
        const size_t available = SHA1_BLOCK_SIZE - ctx->buffer_length;
        const size_t copy_length = (length < available) ? length : available;

        memcpy(&ctx->buffer[ctx->buffer_length], data, copy_length);
        ctx->buffer_length += copy_length;
        data += copy_length;
        length -= copy_length;

        if(ctx->buffer_length == SHA1_BLOCK_SIZE) {
            sha1_transform(ctx, ctx->buffer);
            ctx->buffer_length = 0U;
        }
    }
}

static void sha1_final(Sha1Context* ctx, uint8_t digest[SHA1_DIGEST_SIZE]) {
    const uint64_t original_bit_count = ctx->bit_count;

    const uint8_t marker = 0x80U;
    sha1_update(ctx, &marker, 1U);

    const uint8_t zero = 0U;
    while(ctx->buffer_length != 56U) {
        sha1_update(ctx, &zero, 1U);
    }

    uint8_t length_bytes[8];
    for(uint8_t i = 0U; i < 8U; i++) {
        length_bytes[7U - i] =
            (uint8_t)(original_bit_count >> (i * 8U));
    }

    sha1_update(ctx, length_bytes, sizeof(length_bytes));

    for(uint8_t i = 0U; i < 5U; i++) {
        digest[(i * 4U)] =
            (uint8_t)(ctx->state[i] >> 24U);
        digest[(i * 4U) + 1U] =
            (uint8_t)(ctx->state[i] >> 16U);
        digest[(i * 4U) + 2U] =
            (uint8_t)(ctx->state[i] >> 8U);
        digest[(i * 4U) + 3U] =
            (uint8_t)(ctx->state[i]);
    }
}

static void hmac_sha1(
    const uint8_t* key,
    size_t key_length,
    const uint8_t* data,
    size_t data_length,
    uint8_t output[SHA1_DIGEST_SIZE]) {

    uint8_t normalized_key[SHA1_BLOCK_SIZE] = {0};
    uint8_t inner_pad[SHA1_BLOCK_SIZE];
    uint8_t outer_pad[SHA1_BLOCK_SIZE];
    uint8_t inner_digest[SHA1_DIGEST_SIZE];

    if(key_length > SHA1_BLOCK_SIZE) {
        Sha1Context key_ctx;
        sha1_init(&key_ctx);
        sha1_update(&key_ctx, key, key_length);
        sha1_final(&key_ctx, normalized_key);
    } else {
        memcpy(normalized_key, key, key_length);
    }

    for(size_t i = 0U; i < SHA1_BLOCK_SIZE; i++) {
        inner_pad[i] = normalized_key[i] ^ 0x36U;
        outer_pad[i] = normalized_key[i] ^ 0x5CU;
    }

    Sha1Context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, inner_pad, sizeof(inner_pad));
    sha1_update(&ctx, data, data_length);
    sha1_final(&ctx, inner_digest);

    sha1_init(&ctx);
    sha1_update(&ctx, outer_pad, sizeof(outer_pad));
    sha1_update(&ctx, inner_digest, sizeof(inner_digest));
    sha1_final(&ctx, output);

    /*
     * These buffers contain only public self-test material at present.
     * The same cleanup pattern will become mandatory once real key material
     * is introduced.
     */
    memset(normalized_key, 0, sizeof(normalized_key));
    memset(inner_pad, 0, sizeof(inner_pad));
    memset(outer_pad, 0, sizeof(outer_pad));
    memset(inner_digest, 0, sizeof(inner_digest));
    memset(&ctx, 0, sizeof(ctx));
}

/**
 * @brief Verify HMAC-SHA1 against RFC 2202 test case 1.
 *
 * Key:       20 bytes of 0x0b
 * Challenge: ASCII "Hi There"
 * Expected:  b617318655057264e28bc0b6fb378c8ef146be00
 *
 * @return true only when the computed result exactly matches the published
 *         expected digest.
 */
static bool hmac_sha1_self_test(void) {
    static const uint8_t test_key[20] = {
        0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
        0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
        0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
        0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
    };

    static const uint8_t test_challenge[] = "Hi There";

    static const uint8_t expected[SHA1_DIGEST_SIZE] = {
        0xB6, 0x17, 0x31, 0x86, 0x55,
        0x05, 0x72, 0x64, 0xE2, 0x8B,
        0xC0, 0xB6, 0xFB, 0x37, 0x8C,
        0x8E, 0xF1, 0x46, 0xBE, 0x00,
    };

    uint8_t result[SHA1_DIGEST_SIZE];

    hmac_sha1(
        test_key,
        sizeof(test_key),
        test_challenge,
        sizeof(test_challenge) - 1U,
        result);

    const bool passed =
        memcmp(result, expected, SHA1_DIGEST_SIZE) == 0;

    memset(result, 0, sizeof(result));
    return passed;
}



/* --------------------------------------------------------------------------
 * Provisioned HMAC Key
 * -------------------------------------------------------------------------- */

/**
 * On-disk representation of the device's HMAC credential.
 *
 * The credential is deliberately stored separately from state.bin. This makes
 * the distinction between local authorization data and KeePass cryptographic
 * key material explicit and allows recovery/reset handling to evolve without
 * changing the ordinary authentication-state format.
 *
 * SECURITY LIMITATION:
 * This is a development implementation stored on the microSD card. The
 * Flipper Zero does not provide a general-purpose secure element for arbitrary
 * application secrets, so physical access to the storage may expose this key.
 */
typedef struct {
    uint8_t version;
    uint8_t key[HMAC_KEY_SIZE];
} KeePassKeyCredential;

/**
 * Load a previously provisioned HMAC key.
 *
 * Returns false if the credential file is absent, malformed, or incompatible.
 * The caller can then treat the installation as not yet provisioned.
 */
static bool load_hmac_key(uint8_t key[HMAC_KEY_SIZE]) {
    bool valid = false;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, KEY_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        KeePassKeyCredential credential = {0};
        const uint16_t bytes_read =
            storage_file_read(file, &credential, sizeof(credential));

        if(bytes_read == sizeof(credential) &&
           credential.version == KEY_VERSION) {
            memcpy(key, credential.key, HMAC_KEY_SIZE);
            valid = true;
        }

        memset(&credential, 0, sizeof(credential));
        storage_file_close(file);
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return valid;
}

/**
 * Persist a newly generated HMAC credential.
 *
 * The file is replaced atomically from the application's point of view: a
 * provisioning attempt either writes the complete fixed-size structure or a
 * later load treats it as invalid.
 */
static bool save_hmac_key(const uint8_t key[HMAC_KEY_SIZE]) {
    bool saved = false;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, STATE_DIR);

    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, KEY_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        KeePassKeyCredential credential = {0};
        credential.version = KEY_VERSION;
        memcpy(credential.key, key, HMAC_KEY_SIZE);

        const uint16_t bytes_written =
            storage_file_write(file, &credential, sizeof(credential));

        saved = (bytes_written == sizeof(credential));

        memset(&credential, 0, sizeof(credential));
        storage_file_close(file);
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return saved;
}

/**
 * Generate and persist a fresh 160-bit HMAC-SHA1 key.
 *
 * Random bytes come directly from Flipper's hardware abstraction layer. The
 * generated key is never displayed, logged, or compiled into the application.
 */
static bool provision_hmac_key(uint8_t key[HMAC_KEY_SIZE]) {
    furi_hal_random_fill_buf(key, HMAC_KEY_SIZE);

    if(!save_hmac_key(key)) {
        memset(key, 0, HMAC_KEY_SIZE);
        return false;
    }

    return true;
}

/* --------------------------------------------------------------------------
 * Runtime Application State
 * -------------------------------------------------------------------------- */

typedef struct {
    FuriMessageQueue* input_queue;
    ViewPort* viewport;

    AppMode mode;

    uint8_t failures;
    uint32_t locked_until;
    uint32_t authorized_until;

    uint8_t sequence[MAX_SEQUENCE_LENGTH];
    uint8_t sequence_length;

    uint8_t entry[MAX_SEQUENCE_LENGTH];
    uint8_t entry_length;

    bool hmac_self_test_passed;

    /** True when a valid installation-specific HMAC credential is loaded. */
    bool hmac_key_provisioned;

    /**
     * Installation-specific HMAC credential.
     * Kept in RAM only while the app is running and cleared during cleanup.
     */
    uint8_t hmac_key[HMAC_KEY_SIZE];
} KeePassKeyApp;

/* --------------------------------------------------------------------------
 * Authentication and Storage Helpers
 * -------------------------------------------------------------------------- */

/**
 * Return true when a button is one of the four directions accepted by the
 * authentication sequence. OK and Back remain control buttons.
 */
static bool is_arrow(InputKey key) {
    return key == InputKeyUp ||
           key == InputKeyDown ||
           key == InputKeyLeft ||
           key == InputKeyRight;
}

/**
 * Convert a Flipper directional key into the compact value stored on disk.
 * Zero is reserved as an invalid/unset value.
 */
static uint8_t encode_arrow(InputKey key) {
    switch(key) {
    case InputKeyUp: return 1U;
    case InputKeyDown: return 2U;
    case InputKeyLeft: return 3U;
    case InputKeyRight: return 4U;
    default: return 0U;
    }
}

/** Validate a direction value read from persistent storage. */
static bool valid_stored_arrow(uint8_t value) {
    return value >= 1U && value <= 4U;
}

/**
 * Return the progressive delay applied after consecutive failed attempts.
 * The delay tops out at five minutes; failed-attempt history remains
 * persistent across app restarts.
 */
static uint32_t get_lockout_delay(uint8_t failures) {
    if(failures <= 3U) return 1000U;
    if(failures == 4U) return 5000U;
    if(failures == 5U) return 15000U;
    if(failures == 6U) return 60000U;
    return 300000U;
}

/**
 * Check whether the current lockout deadline is still in the future.
 * Signed tick subtraction keeps the comparison safe across tick wraparound.
 */
static bool is_locked_out(const KeePassKeyApp* app) {
    const int32_t delta = (int32_t)(app->locked_until - furi_get_tick());
    return delta > 0;
}

/** Return the active lockout time in whole seconds, rounded upward. */
static uint32_t seconds_remaining(const KeePassKeyApp* app) {
    if(!is_locked_out(app)) return 0U;

    const uint32_t remaining_ticks = app->locked_until - furi_get_tick();
    const uint32_t frequency = furi_kernel_get_tick_frequency();
    return (remaining_ticks + frequency - 1U) / frequency;
}

/**
 * Load and validate the user's local configuration from the microSD card.
 *
 * A missing, incompatible, or malformed state file is treated as
 * unprovisioned and causes first-run setup to begin.
 *
 * The directional sequence is local authorization data only. The future
 * KeePass HMAC secret will be stored separately.
 */
static bool load_state(KeePassKeyApp* app) {
    bool valid = false;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, STATE_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        KeePassPersistentState state = {0};
        const uint16_t bytes_read = storage_file_read(file, &state, sizeof(state));

        if(bytes_read == sizeof(state) &&
           state.version == STATE_VERSION &&
           state.sequence_length >= MIN_SEQUENCE_LENGTH &&
           state.sequence_length <= MAX_SEQUENCE_LENGTH) {

            valid = true;
            for(uint8_t i = 0U; i < state.sequence_length; i++) {
                if(!valid_stored_arrow(state.sequence[i])) {
                    valid = false;
                    break;
                }
            }

            if(valid) {
                app->failures = state.failures;
                app->sequence_length = state.sequence_length;
                memcpy(app->sequence, state.sequence, state.sequence_length);
            }
        }

        storage_file_close(file);
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return valid;
}

/**
 * Persist the configured directional sequence and failed-attempt counter.
 *
 * This file deliberately contains no KeePass cryptographic key material.
 */
static void save_state(const KeePassKeyApp* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, STATE_DIR);

    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, STATE_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        KeePassPersistentState state = {0};
        state.version = STATE_VERSION;
        state.failures = app->failures;
        state.sequence_length = app->sequence_length;
        memcpy(state.sequence, app->sequence, app->sequence_length);

        storage_file_write(file, &state, sizeof(state));
        storage_file_close(file);

        memset(&state, 0, sizeof(state));
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/** Clear temporary sequence-entry data as soon as an attempt is finished. */
static void clear_entry(KeePassKeyApp* app) {
    memset(app->entry, 0, sizeof(app->entry));
    app->entry_length = 0U;
}

/**
 * Compare two complete directional sequences without exiting on the first
 * mismatch. This avoids making the mismatch position observable through the
 * application's comparison flow.
 */
static bool entries_match(
    const uint8_t* a,
    const uint8_t* b,
    uint8_t length) {

    uint8_t difference = 0U;
    for(uint8_t i = 0U; i < length; i++) {
        difference |= (uint8_t)(a[i] ^ b[i]);
    }
    return difference == 0U;
}

/**
 * Draw sequence progress without revealing which directions were entered.
 * A numeric counter also supports sequences too long for individual dots.
 */
static void draw_progress(Canvas* canvas, uint8_t entered, uint8_t total) {
    char buffer[24];
    snprintf(
        buffer,
        sizeof(buffer),
        "%u / %u directions",
        (unsigned int)entered,
        (unsigned int)total);
    canvas_draw_str(canvas, 24, 47, buffer);
}

/* --------------------------------------------------------------------------
 * User Interface
 * -------------------------------------------------------------------------- */

/** Render the screen appropriate to the current application state. */
static void draw_callback(Canvas* canvas, void* context) {
    KeePassKeyApp* app = context;
    canvas_clear(canvas);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 28, 12, "KeePass Key");
    canvas_set_font(canvas, FontSecondary);

    if(app->mode == AppModeSetupCreate) {
        canvas_draw_str(canvas, 20, 27, "FIRST-TIME SETUP");
        canvas_draw_str(canvas, 10, 39, "Create arrow sequence");
        draw_progress(canvas, app->entry_length, MAX_SEQUENCE_LENGTH);

        if(app->entry_length >= MIN_SEQUENCE_LENGTH) {
            canvas_draw_str(canvas, 11, 61, "OK save  BACK undo");
        } else {
            canvas_draw_str(canvas, 9, 61, "8+ arrows  BACK undo");
        }
        return;
    }

    if(app->mode == AppModeSetupConfirm) {
        canvas_draw_str(canvas, 18, 27, "CONFIRM SEQUENCE");
        canvas_draw_str(canvas, 12, 39, "Enter it once more");
        draw_progress(canvas, app->entry_length, app->sequence_length);
        canvas_draw_str(canvas, 24, 61, "BACK to restart");
        return;
    }

    if(app->mode == AppModeAuthorized) {
        canvas_draw_str(canvas, 37, 24, "AUTHORIZED");

        canvas_draw_str(
            canvas,
            24,
            38,
            app->hmac_key_provisioned ? "KEY: PROVISIONED" : "KEY: MISSING");

        canvas_draw_str(
            canvas,
            24,
            50,
            app->hmac_self_test_passed ? "HMAC TEST: PASS" : "HMAC TEST: FAIL");

        canvas_draw_str(canvas, 27, 63, "BACK to relock");
        return;
    }

    if(is_locked_out(app)) {
        char buffer[32];
        canvas_draw_str(canvas, 39, 29, "LOCKED");
        snprintf(
            buffer,
            sizeof(buffer),
            "Wait %lu seconds",
            (unsigned long)seconds_remaining(app));
        canvas_draw_str(canvas, 25, 45, buffer);
        canvas_draw_str(canvas, 32, 61, "BACK to exit");
        return;
    }

    if(app->mode == AppModeIncorrect) {
        canvas_draw_str(canvas, 31, 27, "Incorrect");
        canvas_draw_str(canvas, 18, 43, "Press OK to retry");
        canvas_draw_str(canvas, 32, 61, "BACK to exit");
        return;
    }

    canvas_draw_str(canvas, 25, 29, "Enter sequence");
    draw_progress(canvas, app->entry_length, app->sequence_length);
    canvas_draw_str(canvas, 30, 61, "BACK to exit");
}

/**
 * Queue hardware input for processing by the main loop. Keeping authentication
 * logic out of the callback makes state transitions easier to reason about.
 */
static void input_callback(InputEvent* input_event, void* context) {
    KeePassKeyApp* app = context;
    furi_message_queue_put(app->input_queue, input_event, FuriWaitForever);
}

/**
 * Record a failed authentication attempt, persist it immediately, and start
 * the corresponding progressive lockout period.
 */
static void apply_failure(KeePassKeyApp* app) {
    if(app->failures < UINT8_MAX) {
        app->failures++;
    }

    save_state(app);

    const uint32_t delay_ms = get_lockout_delay(app->failures);
    const uint32_t delay_ticks =
        (delay_ms * furi_kernel_get_tick_frequency()) / 1000U;

    app->locked_until = furi_get_tick() + delay_ticks;
    app->mode = AppModeIncorrect;
    clear_entry(app);
}

/**
 * Enter the temporary authorized state after a correct full sequence.
 * A successful authentication clears the persistent failure counter.
 */
static void begin_authorization(KeePassKeyApp* app) {
    app->failures = 0U;
    save_state(app);

    /*
     * Migration path for users of the previous demo build: if local setup
     * already exists but no credential has been created yet, provision it only
     * after a successful local authentication.
     */
    if(!app->hmac_key_provisioned) {
        app->hmac_key_provisioned =
            provision_hmac_key(app->hmac_key);
    }

    const uint32_t auth_ticks =
        (AUTH_TIMEOUT_MS * furi_kernel_get_tick_frequency()) / 1000U;

    app->authorized_until = furi_get_tick() + auth_ticks;
    app->mode = AppModeAuthorized;
    clear_entry(app);
}

/* --------------------------------------------------------------------------
 * Application Entry Point
 * -------------------------------------------------------------------------- */

/**
 * Application entry point. Initializes persistent state and GUI resources,
 * performs first-run setup when necessary, and runs the authentication loop.
 */
int32_t keepass_key_app(void* p) {
    UNUSED(p);

    KeePassKeyApp* app = malloc(sizeof(KeePassKeyApp));
    memset(app, 0, sizeof(KeePassKeyApp));

    app->hmac_self_test_passed = hmac_sha1_self_test();
    app->hmac_key_provisioned = load_hmac_key(app->hmac_key);

    const bool provisioned = load_state(app);

    if(provisioned) {
        app->mode = AppModeLocked;

        if(app->failures > 0U) {
            const uint32_t delay_ms = get_lockout_delay(app->failures);
            const uint32_t delay_ticks =
                (delay_ms * furi_kernel_get_tick_frequency()) / 1000U;
            app->locked_until = furi_get_tick() + delay_ticks;
        }
    } else {
        app->mode = AppModeSetupCreate;
    }

    app->input_queue = furi_message_queue_alloc(8U, sizeof(InputEvent));
    app->viewport = view_port_alloc();

    view_port_draw_callback_set(app->viewport, draw_callback, app);
    view_port_input_callback_set(app->viewport, input_callback, app);

    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, app->viewport, GuiLayerFullscreen);

    bool running = true;

    while(running) {
        if(app->mode == AppModeAuthorized) {
            const int32_t remaining =
                (int32_t)(app->authorized_until - furi_get_tick());

            if(remaining <= 0) {
                app->authorized_until = 0U;
                app->mode = AppModeLocked;
                clear_entry(app);
                view_port_update(app->viewport);
            }
        }

        InputEvent event;
        const FuriStatus status =
            furi_message_queue_get(app->input_queue, &event, 250U);

        if(status != FuriStatusOk) {
            view_port_update(app->viewport);
            continue;
        }

        if(event.type != InputTypeShort) {
            continue;
        }

        /* First-run sequence creation. */
        if(app->mode == AppModeSetupCreate) {
            if(is_arrow(event.key) && app->entry_length < MAX_SEQUENCE_LENGTH) {
                app->entry[app->entry_length++] = encode_arrow(event.key);
            } else if(event.key == InputKeyBack) {
                if(app->entry_length > 0U) {
                    app->entry[--app->entry_length] = 0U;
                } else {
                    running = false;
                }
            } else if(event.key == InputKeyOk &&
                      app->entry_length >= MIN_SEQUENCE_LENGTH) {
                app->sequence_length = app->entry_length;
                memcpy(app->sequence, app->entry, app->entry_length);
                clear_entry(app);
                app->mode = AppModeSetupConfirm;
            }

            view_port_update(app->viewport);
            continue;
        }

        /* Confirmation must match only after the full sequence is entered. */
        if(app->mode == AppModeSetupConfirm) {
            if(event.key == InputKeyBack) {
                memset(app->sequence, 0, sizeof(app->sequence));
                app->sequence_length = 0U;
                clear_entry(app);
                app->mode = AppModeSetupCreate;
            } else if(is_arrow(event.key) &&
                      app->entry_length < app->sequence_length) {
                app->entry[app->entry_length++] = encode_arrow(event.key);

                if(app->entry_length == app->sequence_length) {
                    if(entries_match(
                           app->entry,
                           app->sequence,
                           app->sequence_length)) {
                        app->failures = 0U;
                        save_state(app);

                        /*
                         * First-run provisioning happens only after the user
                         * has successfully confirmed their local sequence.
                         */
                        if(!app->hmac_key_provisioned) {
                            app->hmac_key_provisioned =
                                provision_hmac_key(app->hmac_key);
                        }

                        clear_entry(app);
                        app->mode = AppModeLocked;
                    } else {
                        /*
                         * Do not disclose which position differed. Restart the
                         * setup process and require the user to create it again.
                         */
                        memset(app->sequence, 0, sizeof(app->sequence));
                        app->sequence_length = 0U;
                        clear_entry(app);
                        app->mode = AppModeSetupCreate;
                    }
                }
            }

            view_port_update(app->viewport);
            continue;
        }

        if(event.key == InputKeyBack) {
            if(app->mode == AppModeAuthorized) {
                app->authorized_until = 0U;
                app->mode = AppModeLocked;
                clear_entry(app);
            } else {
                running = false;
            }

            view_port_update(app->viewport);
            continue;
        }

        if(app->mode == AppModeAuthorized) {
            continue;
        }

        if(is_locked_out(app)) {
            continue;
        }

        if(app->mode == AppModeIncorrect) {
            if(event.key == InputKeyOk) {
                app->mode = AppModeLocked;
                clear_entry(app);
                view_port_update(app->viewport);
            }
            continue;
        }

        if(app->mode == AppModeLocked && is_arrow(event.key)) {
            if(app->entry_length < app->sequence_length) {
                app->entry[app->entry_length++] = encode_arrow(event.key);
            }

            if(app->entry_length == app->sequence_length) {
                if(entries_match(
                       app->entry,
                       app->sequence,
                       app->sequence_length)) {
                    begin_authorization(app);
                } else {
                    apply_failure(app);
                }
            }

            view_port_update(app->viewport);
        }
    }

    gui_remove_view_port(gui, app->viewport);
    furi_record_close(RECORD_GUI);

    view_port_free(app->viewport);
    furi_message_queue_free(app->input_queue);

    memset(app->hmac_key, 0, sizeof(app->hmac_key));
    memset(app->sequence, 0, sizeof(app->sequence));
    memset(app->entry, 0, sizeof(app->entry));
    memset(app, 0, sizeof(KeePassKeyApp));
    free(app);

    return 0;
}
