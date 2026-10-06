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
 *   - Authenticated recovery-key display using non-clipping two-line pages.
 *   - Manual recovery-key import for replacement/reprovisioned devices.
 *   - Short non-secret fingerprint for recovery verification.
 *   - Five-minute inactivity timeout while viewing or restoring a recovery key.
 *   - Development challenge-response using the provisioned HMAC credential.
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
#include <cli/cli.h>

#define MIN_SEQUENCE_LENGTH 8U
#define MAX_SEQUENCE_LENGTH 32U
#define AUTH_TIMEOUT_MS 30000U
#define RECOVERY_TIMEOUT_MS 300000U

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
    AppModeRecoveryWarning,
    AppModeRecoveryDisplay,
    AppModeDevHmacTest,
    AppModeProvisionChoice,
    AppModeRecoveryImport,
    AppModeRecoveryImported,
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

    /** Which half of the recovery key is currently displayed (0 or 1). */
    uint8_t recovery_page;

    /**
     * Temporary recovery-import buffer.
     * Each entry is one hexadecimal nibble (0-15), not an ASCII character.
     */
    uint8_t recovery_import[HMAC_KEY_SIZE * 2U];
    uint8_t recovery_import_length;
    uint8_t recovery_import_digit;
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



/**
 * Derive a short, non-secret identifier for the provisioned credential.
 *
 * This is NOT an authentication value and must never be used as one. It exists
 * only so a user can verify that a restored credential is byte-for-byte the
 * same as the original without displaying the credential itself.
 *
 * The fingerprint is the first four bytes of HMAC-SHA1(key, fixed public
 * label), displayed as eight hexadecimal characters. Revealing 32 bits of an
 * HMAC output is acceptable for this development verification purpose, but the
 * value should still be treated only as an identifier.
 */
static void make_key_fingerprint(
    const uint8_t key[HMAC_KEY_SIZE],
    char output[9]) {

    static const uint8_t label[] = "KeePass Key fingerprint v1";
    uint8_t digest[SHA1_DIGEST_SIZE];

    hmac_sha1(
        key,
        HMAC_KEY_SIZE,
        label,
        sizeof(label) - 1U,
        digest);

    static const char hex[] = "0123456789ABCDEF";
    for(uint8_t i = 0U; i < 4U; i++) {
        output[i * 2U] = hex[(digest[i] >> 4U) & 0x0FU];
        output[(i * 2U) + 1U] = hex[digest[i] & 0x0FU];
    }
    output[8] = '\0';

    memset(digest, 0, sizeof(digest));
}



/* --------------------------------------------------------------------------
 * Development Challenge-Response Test
 * -------------------------------------------------------------------------- */

/**
 * Calculate a deterministic HMAC-SHA1 response using the REAL provisioned key.
 *
 * The fixed challenge is public development data. Only the first four bytes
 * of the response are shown, which is enough to compare independently on the
 * PC without exposing the device credential.
 */
static void make_dev_response_id(
    const uint8_t key[HMAC_KEY_SIZE],
    char output[9]) {

    static const uint8_t challenge[] =
        "KeePass Key development challenge v1";
    uint8_t response[SHA1_DIGEST_SIZE];

    hmac_sha1(
        key,
        HMAC_KEY_SIZE,
        challenge,
        sizeof(challenge) - 1U,
        response);

    static const char hex[] = "0123456789ABCDEF";
    for(uint8_t i = 0U; i < 4U; i++) {
        output[i * 2U] = hex[(response[i] >> 4U) & 0x0FU];
        output[(i * 2U) + 1U] = hex[response[i] & 0x0FU];
    }
    output[8] = '\0';

    memset(response, 0, sizeof(response));
}


/* --------------------------------------------------------------------------
 * USB Development Challenge-Response
 * -------------------------------------------------------------------------- */

#define USB_CHALLENGE_MAX_SIZE 64U

/**
 * Convert a single hexadecimal character to a nibble.
 */
static bool hex_to_nibble(char c, uint8_t* value) {
    if(c >= '0' && c <= '9') {
        *value = (uint8_t)(c - '0');
        return true;
    }

    if(c >= 'A' && c <= 'F') {
        *value = (uint8_t)(c - 'A' + 10);
        return true;
    }

    if(c >= 'a' && c <= 'f') {
        *value = (uint8_t)(c - 'a' + 10);
        return true;
    }

    return false;
}

/**
 * CLI command used only for the development transport test.
 *
 * Usage from the Flipper serial CLI:
 *
 *     keepass_challenge 001122AABB...
 *
 * The host supplies an arbitrary hexadecimal challenge. The command computes
 * HMAC-SHA1 with the provisioned device credential and returns the complete
 * 20-byte response as 40 hexadecimal characters.
 *
 * The key is never printed or copied to the host.
 */
static void keepass_challenge_cli(PipeSide* pipe, FuriString* args, void* context) {
    UNUSED(pipe);

    KeePassKeyApp* app = context;

    if(!app->hmac_key_provisioned) {
        printf("ERR key_missing\r\n");
        return;
    }

    const char* input = furi_string_get_cstr(args);

    while(*input == ' ' || *input == '\t') {
        input++;
    }

    size_t hex_length = strlen(input);

    while(hex_length > 0U &&
          (input[hex_length - 1U] == ' ' ||
           input[hex_length - 1U] == '\t' ||
           input[hex_length - 1U] == '\r' ||
           input[hex_length - 1U] == '\n')) {
        hex_length--;
    }

    if(hex_length == 0U ||
       (hex_length & 1U) != 0U ||
       hex_length > (USB_CHALLENGE_MAX_SIZE * 2U)) {
        printf("ERR challenge_length\r\n");
        return;
    }

    uint8_t challenge[USB_CHALLENGE_MAX_SIZE];
    uint8_t response[SHA1_DIGEST_SIZE];
    memset(challenge, 0, sizeof(challenge));
    memset(response, 0, sizeof(response));

    const size_t challenge_length = hex_length / 2U;

    for(size_t i = 0U; i < challenge_length; i++) {
        uint8_t high;
        uint8_t low;

        if(!hex_to_nibble(input[i * 2U], &high) ||
           !hex_to_nibble(input[(i * 2U) + 1U], &low)) {
            printf("ERR invalid_hex\r\n");
            memset(challenge, 0, sizeof(challenge));
            return;
        }

        challenge[i] = (uint8_t)((high << 4U) | low);
    }

    hmac_sha1(
        app->hmac_key,
        HMAC_KEY_SIZE,
        challenge,
        challenge_length,
        response);

    printf("OK ");
    for(size_t i = 0U; i < SHA1_DIGEST_SIZE; i++) {
        printf("%02X", response[i]);
    }
    printf("\r\n");

    memset(challenge, 0, sizeof(challenge));
    memset(response, 0, sizeof(response));
}

/* --------------------------------------------------------------------------
 * Recovery Key Helpers
 * -------------------------------------------------------------------------- */

/**
 * Convert one byte to two uppercase hexadecimal characters.
 */
static void byte_to_hex(uint8_t value, char* output) {
    static const char hex[] = "0123456789ABCDEF";
    output[0] = hex[(value >> 4U) & 0x0FU];
    output[1] = hex[value & 0x0FU];
}

/**
 * Format ten bytes of the credential as five four-character groups.
 *
 * Splitting the 40-character recovery value over two pages keeps it readable
 * on the Flipper display and makes manual transcription less error-prone.
 */
static void format_recovery_line(
    const uint8_t key[HMAC_KEY_SIZE],
    uint8_t page,
    uint8_t line,
    char output[13]) {

    /*
     * Each page contains ten bytes (20 hex characters), split across two
     * deliberately short lines. Each line represents five bytes / ten hex
     * characters and is formatted as:
     *
     *     XXXX XXXX XX
     *
     * This avoids relying on the full 128-pixel display width and makes
     * clipping immediately obvious.
     */
    const uint8_t byte_offset =
        (uint8_t)((page * 10U) + (line * 5U));

    size_t position = 0U;

    for(uint8_t i = 0U; i < 5U; i++) {
        byte_to_hex(key[byte_offset + i], &output[position]);
        position += 2U;

        if(i == 1U || i == 3U) {
            output[position++] = ' ';
        }
    }

    output[position] = '\0';
}

/** Return the printable hexadecimal character for a nibble value. */
static char hex_digit_char(uint8_t value) {
    static const char hex[] = "0123456789ABCDEF";
    return hex[value & 0x0FU];
}

/** Clear all temporary recovery-import material from RAM. */
static void clear_recovery_import(KeePassKeyApp* app) {
    memset(app->recovery_import, 0, sizeof(app->recovery_import));
    app->recovery_import_length = 0U;
    app->recovery_import_digit = 0U;
}

/**
 * Give recovery viewing/import its own five-minute inactivity window.
 *
 * Normal authorization remains limited to 30 seconds. Recovery operations need
 * longer because the user may be carefully transcribing or entering forty
 * hexadecimal characters. Relevant button presses refresh this deadline.
 */
static void refresh_recovery_timeout(KeePassKeyApp* app) {
    const uint32_t timeout_ticks =
        (RECOVERY_TIMEOUT_MS * furi_kernel_get_tick_frequency()) / 1000U;

    app->authorized_until = furi_get_tick() + timeout_ticks;
}

/**
 * Convert the forty entered hexadecimal nibbles into the twenty-byte HMAC key.
 *
 * The temporary decoded key is saved using the same credential format as a
 * locally generated key. It is copied into the live application state only
 * after the persistent write succeeds.
 */
static bool finish_recovery_import(KeePassKeyApp* app) {
    if(app->recovery_import_length != (HMAC_KEY_SIZE * 2U)) {
        return false;
    }

    uint8_t restored_key[HMAC_KEY_SIZE];

    for(uint8_t i = 0U; i < HMAC_KEY_SIZE; i++) {
        restored_key[i] =
            (uint8_t)((app->recovery_import[i * 2U] << 4U) |
                      app->recovery_import[(i * 2U) + 1U]);
    }

    const bool saved = save_hmac_key(restored_key);

    if(saved) {
        memcpy(app->hmac_key, restored_key, HMAC_KEY_SIZE);
        app->hmac_key_provisioned = true;
    }

    memset(restored_key, 0, sizeof(restored_key));
    clear_recovery_import(app);
    return saved;
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

    if(app->mode == AppModeProvisionChoice) {
        canvas_draw_str(canvas, 24, 24, "DEVICE KEY SETUP");
        canvas_draw_str(canvas, 7, 38, "UP generate new key");
        canvas_draw_str(canvas, 5, 50, "DOWN restore backup");
        canvas_draw_str(canvas, 27, 63, "BACK to relock");
        return;
    }

    if(app->mode == AppModeRecoveryImport) {
        char progress[24];
        char selected[20];

        snprintf(
            progress,
            sizeof(progress),
            "%u / 40 characters",
            (unsigned int)app->recovery_import_length);

        snprintf(
            selected,
            sizeof(selected),
            "Selected: %c",
            hex_digit_char(app->recovery_import_digit));

        canvas_draw_str(canvas, 20, 22, "RESTORE KEY");
        canvas_draw_str(canvas, 18, 35, progress);
        canvas_draw_str(canvas, 28, 48, selected);
        canvas_draw_str(canvas, 3, 62, "UP/DN choose OK add");
        return;
    }

    if(app->mode == AppModeRecoveryImported) {
        canvas_draw_str(canvas, 20, 25, "KEY RESTORED");
        canvas_draw_str(canvas, 8, 41, "Backup saved to device");
        canvas_draw_str(canvas, 17, 60, "OK continue");
        return;
    }

    if(app->mode == AppModeRecoveryWarning) {
        canvas_draw_str(canvas, 25, 25, "RECOVERY KEY");
        canvas_draw_str(canvas, 8, 38, "Anyone with it can");
        canvas_draw_str(canvas, 12, 49, "clone your device");
        canvas_draw_str(canvas, 5, 62, "Hold OK show  BACK");
        return;
    }

    if(app->mode == AppModeRecoveryDisplay) {
        char recovery_line_1[13];
        char recovery_line_2[13];

        format_recovery_line(
            app->hmac_key,
            app->recovery_page,
            0U,
            recovery_line_1);
        format_recovery_line(
            app->hmac_key,
            app->recovery_page,
            1U,
            recovery_line_2);

        char page_label[20];
        snprintf(
            page_label,
            sizeof(page_label),
            "PART %u OF 2",
            (unsigned int)(app->recovery_page + 1U));

        canvas_draw_str(canvas, 20, 19, "RECOVERY KEY");
        canvas_draw_str(canvas, 39, 30, page_label);

        /*
         * Two short fixed-width-ish rows are intentionally used instead of
         * attempting to fit all 20 hex characters on one line. Every page
         * therefore exposes exactly 20 characters: ten on each row.
         */
        canvas_set_font(canvas, FontKeyboard);
        canvas_draw_str(canvas, 25, 43, recovery_line_1);
        canvas_draw_str(canvas, 25, 53, recovery_line_2);
        canvas_set_font(canvas, FontSecondary);

        canvas_draw_str(
            canvas,
            7,
            64,
            app->recovery_page == 0U ?
                "OK next  BACK hide" :
                "OK done  BACK hide");

        memset(recovery_line_1, 0, sizeof(recovery_line_1));
        memset(recovery_line_2, 0, sizeof(recovery_line_2));
        memset(page_label, 0, sizeof(page_label));
        return;
    }

    if(app->mode == AppModeDevHmacTest) {
        char response_id[9];
        char response_line[24];

        make_dev_response_id(app->hmac_key, response_id);
        snprintf(
            response_line,
            sizeof(response_line),
            "RESULT: %s",
            response_id);

        /*
         * This is deliberately a temporary, sparse test screen. It does not
         * alter the normal authorised UI.
         */
        canvas_draw_str(canvas, 31, 20, "HMAC TEST");
        canvas_draw_str(canvas, 29, 39, response_line);
        canvas_draw_str(canvas, 17, 59, "OK return  BACK relock");

        memset(response_id, 0, sizeof(response_id));
        memset(response_line, 0, sizeof(response_line));
        return;
    }

    if(app->mode == AppModeAuthorized) {
        canvas_draw_str(canvas, 37, 20, "AUTHORIZED");

        canvas_draw_str(
            canvas,
            24,
            32,
            app->hmac_key_provisioned ? "KEY: PROVISIONED" : "KEY: MISSING");

        if(app->hmac_key_provisioned) {
            char fingerprint[9];
            char fingerprint_line[24];

            make_key_fingerprint(app->hmac_key, fingerprint);
            snprintf(
                fingerprint_line,
                sizeof(fingerprint_line),
                "ID: %s",
                fingerprint);
            canvas_draw_str(canvas, 35, 44, fingerprint_line);

            memset(fingerprint, 0, sizeof(fingerprint));
            memset(fingerprint_line, 0, sizeof(fingerprint_line));
        } else {
            canvas_draw_str(canvas, 42, 44, "ID: --------");
        }

        canvas_draw_str(
            canvas,
            24,
            54,
            app->hmac_self_test_passed ? "HMAC TEST: PASS" : "HMAC TEST: FAIL");

        canvas_draw_str(canvas, 6, 64, "Hold OK recovery  BACK");
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

    const uint32_t auth_ticks =
        (AUTH_TIMEOUT_MS * furi_kernel_get_tick_frequency()) / 1000U;

    app->authorized_until = furi_get_tick() + auth_ticks;
    app->mode =
        app->hmac_key_provisioned ? AppModeAuthorized : AppModeProvisionChoice;
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

    /*
     * Temporary development transport: expose a serial CLI command while this
     * app is running. This proves PC -> Flipper -> PC challenge-response before
     * implementing the final KeePassXC/YubiKey-compatible transport.
     */
    CliRegistry* cli_registry = furi_record_open(RECORD_CLI);
    cli_registry_add_command(
        cli_registry,
        "keepass_challenge",
        CliCommandFlagParallelSafe,
        keepass_challenge_cli,
        app);

    bool running = true;

    while(running) {
        if(app->mode == AppModeAuthorized ||
           app->mode == AppModeDevHmacTest ||
           app->mode == AppModeRecoveryWarning ||
           app->mode == AppModeRecoveryDisplay ||
           app->mode == AppModeProvisionChoice ||
           app->mode == AppModeRecoveryImport ||
           app->mode == AppModeRecoveryImported) {
            const int32_t remaining =
                (int32_t)(app->authorized_until - furi_get_tick());

            if(remaining <= 0) {
                app->authorized_until = 0U;
                app->mode = AppModeLocked;
                clear_entry(app);
                clear_recovery_import(app);
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

        /*
         * Recovery disclosure deliberately uses a long OK press. Normal
         * navigation and authentication continue to use short presses.
         */
        const bool short_press = event.type == InputTypeShort;
        const bool long_press = event.type == InputTypeLong;

        if(!short_press && !long_press) {
            continue;
        }

        /*
         * Missing credentials are handled explicitly. UP creates a fresh
         * random key; DOWN starts restoration from a written recovery key.
         */
        if(app->mode == AppModeProvisionChoice && short_press) {
            if(event.key == InputKeyUp) {
                app->hmac_key_provisioned =
                    provision_hmac_key(app->hmac_key);

                if(app->hmac_key_provisioned) {
                    app->mode = AppModeAuthorized;
                }
            } else if(event.key == InputKeyDown) {
                clear_recovery_import(app);
                refresh_recovery_timeout(app);
                app->mode = AppModeRecoveryImport;
            } else if(event.key == InputKeyBack) {
                app->authorized_until = 0U;
                clear_recovery_import(app);
                app->mode = AppModeLocked;
            }

            view_port_update(app->viewport);
            continue;
        }

        /*
         * Recovery import deliberately shows only progress and the currently
         * selected hexadecimal digit. Previously entered credential material
         * is not echoed back to the screen.
         */
        if(app->mode == AppModeRecoveryImport && short_press) {
            if(event.key == InputKeyUp ||
               event.key == InputKeyDown ||
               event.key == InputKeyBack ||
               event.key == InputKeyOk) {
                refresh_recovery_timeout(app);
            }

            if(event.key == InputKeyUp) {
                app->recovery_import_digit =
                    (uint8_t)((app->recovery_import_digit + 1U) & 0x0FU);
            } else if(event.key == InputKeyDown) {
                app->recovery_import_digit =
                    (uint8_t)((app->recovery_import_digit + 15U) & 0x0FU);
            } else if(event.key == InputKeyBack) {
                if(app->recovery_import_length > 0U) {
                    app->recovery_import_length--;
                    app->recovery_import[
                        app->recovery_import_length] = 0U;
                } else {
                    clear_recovery_import(app);
                    app->mode = AppModeProvisionChoice;
                }
            } else if(event.key == InputKeyOk) {
                if(app->recovery_import_length < (HMAC_KEY_SIZE * 2U)) {
                    app->recovery_import[
                        app->recovery_import_length++] =
                        app->recovery_import_digit;
                }

                if(app->recovery_import_length ==
                   (HMAC_KEY_SIZE * 2U)) {
                    if(finish_recovery_import(app)) {
                        app->mode = AppModeRecoveryImported;
                    }
                }
            }

            view_port_update(app->viewport);
            continue;
        }

        if(app->mode == AppModeRecoveryImported && short_press) {
            if(event.key == InputKeyOk) {
                app->mode = AppModeAuthorized;
            } else if(event.key == InputKeyBack) {
                app->authorized_until = 0U;
                app->mode = AppModeLocked;
            }

            view_port_update(app->viewport);
            continue;
        }

        /*
         * Enter the recovery warning only from an already-authorized state.
         * A long press avoids accidental disclosure during normal use.
         */
        if(app->mode == AppModeAuthorized &&
           event.key == InputKeyOk &&
           short_press &&
           app->hmac_key_provisioned) {
            app->mode = AppModeDevHmacTest;
            view_port_update(app->viewport);
            continue;
        }

        if(app->mode == AppModeAuthorized &&
           event.key == InputKeyOk &&
           long_press &&
           app->hmac_key_provisioned) {
            refresh_recovery_timeout(app);
            app->recovery_page = 0U;
            app->mode = AppModeRecoveryWarning;
            view_port_update(app->viewport);
            continue;
        }

        /*
         * The warning requires a second deliberate long OK press before any
         * credential bytes are placed on screen.
         */
        if(app->mode == AppModeDevHmacTest) {
            if(event.key == InputKeyOk && short_press) {
                /*
                 * Return to the normal authorised screen with a fresh normal
                 * authorization window.
                 */
                const uint32_t auth_ticks =
                    (AUTH_TIMEOUT_MS * furi_kernel_get_tick_frequency()) / 1000U;
                app->authorized_until = furi_get_tick() + auth_ticks;
                app->mode = AppModeAuthorized;
            } else if(event.key == InputKeyBack && short_press) {
                begin_authorization(app);
            }

            view_port_update(app->viewport);
            continue;
        }

        if(app->mode == AppModeRecoveryWarning) {
            if(event.key == InputKeyBack && short_press) {
                app->mode = AppModeAuthorized;

                /* Returning to normal authorization restores its 30s window. */
                const uint32_t auth_ticks =
                    (AUTH_TIMEOUT_MS * furi_kernel_get_tick_frequency()) / 1000U;
                app->authorized_until = furi_get_tick() + auth_ticks;
            } else if(event.key == InputKeyOk && long_press) {
                refresh_recovery_timeout(app);
                app->recovery_page = 0U;
                app->mode = AppModeRecoveryDisplay;
            }

            view_port_update(app->viewport);
            continue;
        }

        /*
         * Recovery data is visible only in this state. BACK hides it
         * immediately; OK advances through the two halves and then hides it.
         */
        if(app->mode == AppModeRecoveryDisplay) {
            if((event.key == InputKeyBack || event.key == InputKeyOk) &&
               short_press) {
                refresh_recovery_timeout(app);
            }

            if(event.key == InputKeyBack && short_press) {
                app->recovery_page = 0U;
                app->mode = AppModeAuthorized;

                const uint32_t auth_ticks =
                    (AUTH_TIMEOUT_MS * furi_kernel_get_tick_frequency()) / 1000U;
                app->authorized_until = furi_get_tick() + auth_ticks;
            } else if(event.key == InputKeyOk && short_press) {
                if(app->recovery_page == 0U) {
                    app->recovery_page = 1U;
                } else {
                    app->recovery_page = 0U;
                    app->mode = AppModeAuthorized;

                    const uint32_t auth_ticks =
                        (AUTH_TIMEOUT_MS * furi_kernel_get_tick_frequency()) / 1000U;
                    app->authorized_until = furi_get_tick() + auth_ticks;
                }
            }

            view_port_update(app->viewport);
            continue;
        }

        if(!short_press) {
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
                         * Local authorization setup is now complete. Key
                         * provisioning is a separate explicit choice so a new
                         * installation can either generate a fresh credential
                         * or restore an existing recovery credential.
                         */
                        clear_entry(app);
                        app->mode = AppModeProvisionChoice;

                        const uint32_t auth_ticks =
                            (AUTH_TIMEOUT_MS *
                             furi_kernel_get_tick_frequency()) / 1000U;
                        app->authorized_until =
                            furi_get_tick() + auth_ticks;
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
    memset(app->recovery_import, 0, sizeof(app->recovery_import));
    memset(app->sequence, 0, sizeof(app->sequence));
    memset(app->entry, 0, sizeof(app->entry));
    memset(app, 0, sizeof(KeePassKeyApp));
    cli_registry_delete_command(cli_registry, "keepass_challenge");
    furi_record_close(RECORD_CLI);

    free(app);

    return 0;
}
