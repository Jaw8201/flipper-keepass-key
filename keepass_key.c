/**
 * @file keepass_key.c
 * @brief Local authentication interface for the KeePass Key Flipper Zero
 *        application.
 *
 * This module implements the local user-authentication layer for a
 * Flipper Zero based KeePassXC challenge-response authenticator.
 *
 * Current functionality:
 *   - Directional-button authentication sequence.
 *   - Concealed sequence-entry feedback.
 *   - Progressive authentication-failure delays.
 *   - Persistent failed-attempt state.
 *   - Temporary authenticated ("armed") state.
 *   - Automatic authorization timeout.
 *   - Manual relocking.
 *
 * Planned functionality:
 *   - Cryptographic key provisioning and storage.
 *   - HMAC challenge-response.
 *   - USB communication with the host.
 *   - Single-use authorization for each challenge.
 *
 * SECURITY MODEL
 * --------------
 * The directional sequence is NOT intended to serve as the cryptographic
 * key used to protect a KeePass database.
 *
 * Its purpose is to provide local authorization before this device is
 * permitted to use a separately generated cryptographic secret.
 *
 * The cryptographic secret must therefore remain logically independent
 * of the authentication sequence.
 *
 * IMPORTANT:
 * This implementation is currently developmental and MUST NOT be relied
 * upon to protect a production KeePass database.
 */

#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <storage/storage.h>

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

/**
 * Number of directional inputs required for successful local authentication.
 *
 * Changing this value requires changing secret_sequence[] accordingly.
 */
#define SEQUENCE_LENGTH 8U

/**
 * Maximum duration of an unused authorization window.
 *
 * After successful local authentication, the application automatically
 * returns to the locked state when this interval expires.
 */
#define AUTH_TIMEOUT_MS 30000U

/**
 * Persistent application-state location on the microSD card.
 *
 * Only the failed-attempt counter is stored here. The authentication
 * sequence and future cryptographic key material must not be written to
 * this state file.
 */
#define STATE_DIR EXT_PATH("apps_data/keepass_key")
#define STATE_PATH EXT_PATH("apps_data/keepass_key/state.bin")
#define STATE_VERSION 1U

/**
 * Directional authentication sequence.
 *
 * SECURITY NOTE:
 * This is currently compiled directly into the application binary for
 * development purposes.
 *
 * The production implementation should not use this example sequence.
 * Do not publish or commit the real sequence to a public repository.
 */
static const InputKey secret_sequence[SEQUENCE_LENGTH] = {
    InputKeyUp,
    InputKeyUp,
    InputKeyUp,
    InputKeyUp,
    InputKeyDown,
    InputKeyDown,
    InputKeyDown,
    InputKeyDown,
};

/* --------------------------------------------------------------------------
 * Persistent State
 * -------------------------------------------------------------------------- */

/**
 * @brief Minimal persistent security state.
 *
 * A version field allows the on-disk structure to be changed safely in
 * later releases. The failure counter is deliberately small and contains
 * no authentication sequence or cryptographic secret.
 */
typedef struct {
    uint8_t version;
    uint8_t failures;
} KeePassPersistentState;

/**
 * @brief Save the current failed-attempt counter to the microSD card.
 *
 * @param failures Consecutive failed authentication attempts.
 */
static void save_failure_state(uint8_t failures) {
    Storage* storage = furi_record_open(RECORD_STORAGE);

    storage_common_mkdir(storage, STATE_DIR);

    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, STATE_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        const KeePassPersistentState state = {
            .version = STATE_VERSION,
            .failures = failures,
        };

        storage_file_write(file, &state, sizeof(state));
        storage_file_close(file);
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

/**
 * @brief Load the saved failed-attempt counter.
 *
 * Invalid, missing, or incompatible state files are treated as a clean
 * state rather than being trusted blindly.
 *
 * @return Previously saved consecutive failure count, or zero.
 */
static uint8_t load_failure_state(void) {
    uint8_t failures = 0U;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);

    if(storage_file_open(file, STATE_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        KeePassPersistentState state = {0};

        const uint16_t bytes_read =
            storage_file_read(file, &state, sizeof(state));

        if((bytes_read == sizeof(state)) &&
           (state.version == STATE_VERSION)) {
            failures = state.failures;
        }

        storage_file_close(file);
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);

    return failures;
}

/* --------------------------------------------------------------------------
 * Application State
 * -------------------------------------------------------------------------- */

/**
 * @brief Runtime state for the KeePass Key application.
 *
 * Sensitive state should have the shortest practical lifetime. Future
 * cryptographic material must be explicitly cleared before memory is
 * released or the application returns to the locked state.
 */
typedef struct {
    /** Queue receiving button events from the Flipper input subsystem. */
    FuriMessageQueue* input_queue;

    /** Full-screen viewport used by the application. */
    ViewPort* viewport;

    /** Current position within the expected authentication sequence. */
    uint8_t position;

    /** Number of consecutive failed authentication attempts. */
    uint8_t failures;

    /** True after successful local authentication. */
    bool unlocked;

    /** True when the most recent sequence attempt was incorrect. */
    bool wrong_sequence;

    /**
     * System tick at which the current authentication lockout expires.
     *
     * A value of zero means no lockout has been established.
     */
    uint32_t locked_until;

    /**
     * System tick at which temporary authorization expires.
     *
     * Authorization is intentionally short-lived. Future challenge-response
     * handling will consume this authorization once and immediately relock.
     */
    uint32_t authorized_until;
} KeePassKeyApp;

/* --------------------------------------------------------------------------
 * Input Helpers
 * -------------------------------------------------------------------------- */

/**
 * @brief Determine whether an input key is a permitted sequence direction.
 *
 * Only directional buttons participate in the authentication sequence.
 * OK and Back are intentionally excluded so that they can later be used
 * for explicit authorization and cancellation.
 *
 * @param key Flipper input key.
 * @return true if the key is a directional input; otherwise false.
 */
static bool is_arrow(InputKey key) {
    return key == InputKeyUp ||
           key == InputKeyDown ||
           key == InputKeyLeft ||
           key == InputKeyRight;
}

/* --------------------------------------------------------------------------
 * Authentication Lockout
 * -------------------------------------------------------------------------- */

/**
 * @brief Return the delay applied after a failed authentication attempt.
 *
 * Progressive delays increase the cost of repeatedly attempting local
 * authentication while avoiding destructive behaviour such as automatic
 * key deletion.
 *
 * @param failures Number of consecutive failed attempts.
 * @return Lockout duration in milliseconds.
 */
static uint32_t get_lockout_delay(uint8_t failures) {
    if(failures <= 3U) {
        return 1000U;
    }

    if(failures == 4U) {
        return 5000U;
    }

    if(failures == 5U) {
        return 15000U;
    }

    if(failures == 6U) {
        return 60000U;
    }

    /* Seven or more consecutive failures. */
    return 300000U;
}

/**
 * @brief Determine whether authentication is currently rate-limited.
 *
 * @param app Application state.
 * @return true while the lockout period remains active.
 */
static bool is_locked_out(const KeePassKeyApp* app) {
    return furi_get_tick() < app->locked_until;
}

/**
 * @brief Calculate the remaining lockout period in seconds.
 *
 * The result is rounded upward so that a partial final second is still
 * displayed as one second rather than zero.
 *
 * @param app Application state.
 * @return Remaining lockout duration in seconds.
 */
static uint32_t seconds_remaining(const KeePassKeyApp* app) {
    const uint32_t now = furi_get_tick();

    if(now >= app->locked_until) {
        return 0U;
    }

    const uint32_t remaining_ticks = app->locked_until - now;
    const uint32_t tick_frequency = furi_kernel_get_tick_frequency();

    return (remaining_ticks + tick_frequency - 1U) / tick_frequency;
}

/* --------------------------------------------------------------------------
 * User Interface
 * -------------------------------------------------------------------------- */

/**
 * @brief Render the current application state.
 *
 * Sequence progress is deliberately represented by identical markers.
 * The actual directions entered by the user are never displayed.
 *
 * @param canvas  Flipper graphics canvas.
 * @param context Pointer to KeePassKeyApp.
 */
static void draw_callback(Canvas* canvas, void* context) {
    KeePassKeyApp* app = context;

    canvas_clear(canvas);

    /* Application title. */
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 28, 12, "KeePass Key");

    canvas_set_font(canvas, FontSecondary);

    /* ------------------------------------------------------------------
     * Authorized state
     * ------------------------------------------------------------------ */

    if(app->unlocked) {
        canvas_draw_str(canvas, 37, 31, "AUTHORIZED");
        canvas_draw_str(canvas, 21, 47, "Ready for KeePass");
        canvas_draw_str(canvas, 27, 61, "BACK to relock");
        return;
    }

    /* ------------------------------------------------------------------
     * Authentication lockout
     * ------------------------------------------------------------------ */

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

    /* ------------------------------------------------------------------
     * Failed sequence notification
     * ------------------------------------------------------------------ */

    if(app->wrong_sequence) {
        canvas_draw_str(canvas, 31, 27, "Incorrect");
        canvas_draw_str(canvas, 18, 43, "Press OK to retry");
        canvas_draw_str(canvas, 32, 61, "BACK to exit");

        return;
    }

    /* ------------------------------------------------------------------
     * Sequence entry
     * ------------------------------------------------------------------ */

    canvas_draw_str(canvas, 25, 29, "Enter sequence");

    /*
     * Display only how many inputs have been entered.
     *
     * Filled circles represent entered positions.
     * Empty circles represent remaining positions.
     *
     * The direction associated with each input is intentionally concealed
     * to reduce accidental disclosure to an observer.
     */
    for(uint8_t i = 0U; i < SEQUENCE_LENGTH; i++) {
        const uint8_t x = 29U + (i * 10U);

        if(i < app->position) {
            canvas_draw_disc(canvas, x, 44, 2);
        } else {
            canvas_draw_circle(canvas, x, 44, 2);
        }
    }

    canvas_draw_str(canvas, 30, 61, "BACK to exit");
}

/**
 * @brief Forward hardware input events to the application event queue.
 *
 * Input callbacks should remain lightweight. Authentication processing is
 * therefore performed by the application's main event loop rather than
 * directly inside this callback.
 *
 * @param input_event Input event supplied by the Flipper input subsystem.
 * @param context     Pointer to KeePassKeyApp.
 */
static void input_callback(InputEvent* input_event, void* context) {
    KeePassKeyApp* app = context;

    furi_message_queue_put(
        app->input_queue,
        input_event,
        FuriWaitForever);
}

/* --------------------------------------------------------------------------
 * Application Entry Point
 * -------------------------------------------------------------------------- */

/**
 * @brief KeePass Key application entry point.
 *
 * Initializes application state and GUI resources, processes user input,
 * enforces authentication delays, and releases all resources on exit.
 *
 * @param p Unused Flipper application argument.
 * @return 0 on normal termination.
 */
int32_t keepass_key_app(void* p) {
    UNUSED(p);

    /* ------------------------------------------------------------------
     * Allocate and initialize application state.
     * ------------------------------------------------------------------ */

    KeePassKeyApp* app = malloc(sizeof(KeePassKeyApp));

    /*
     * Explicit initialization is used rather than relying on allocator
     * behaviour. Security-sensitive state should never depend on memory
     * being returned in a particular condition.
     */
    app->position = 0U;
    app->failures = load_failure_state();
    app->unlocked = false;
    app->wrong_sequence = false;
    app->locked_until = 0U;
    app->authorized_until = 0U;

    /*
     * Reapply the appropriate delay when the app is reopened after failed
     * authentication. Closing and relaunching the app therefore does not
     * provide a free reset of the rate limiter.
     */
    if(app->failures > 0U) {
        const uint32_t startup_delay_ms =
            get_lockout_delay(app->failures);

        const uint32_t startup_delay_ticks =
            (startup_delay_ms *
             furi_kernel_get_tick_frequency()) /
            1000U;

        app->locked_until =
            furi_get_tick() + startup_delay_ticks;
    }

    /* ------------------------------------------------------------------
     * Configure input queue.
     * ------------------------------------------------------------------ */

    app->input_queue =
        furi_message_queue_alloc(8U, sizeof(InputEvent));

    /* ------------------------------------------------------------------
     * Configure viewport.
     * ------------------------------------------------------------------ */

    app->viewport = view_port_alloc();

    view_port_draw_callback_set(
        app->viewport,
        draw_callback,
        app);

    view_port_input_callback_set(
        app->viewport,
        input_callback,
        app);

    /* ------------------------------------------------------------------
     * Attach viewport to GUI.
     * ------------------------------------------------------------------ */

    Gui* gui = furi_record_open(RECORD_GUI);

    gui_add_view_port(
        gui,
        app->viewport,
        GuiLayerFullscreen);

    bool running = true;

    /* ------------------------------------------------------------------
     * Main event loop.
     * ------------------------------------------------------------------ */

    while(running) {
        /*
         * Authorization is deliberately temporary. If the authorization
         * window expires before it is used, return to the locked state.
         */
        if(app->unlocked && (furi_get_tick() >= app->authorized_until)) {
            app->unlocked = false;
            app->authorized_until = 0U;
            app->position = 0U;
            app->wrong_sequence = false;

            view_port_update(app->viewport);
        }

        InputEvent event;

        /*
         * A finite queue timeout allows the display to refresh periodically
         * while a lockout countdown is active, even when no buttons are
         * being pressed.
         */
        const FuriStatus status =
            furi_message_queue_get(
                app->input_queue,
                &event,
                250U);

        if(status != FuriStatusOk) {
            view_port_update(app->viewport);
            continue;
        }

        /*
         * Process one event per deliberate short button press.
         *
         * Ignoring press/repeat/release events prevents a held button from
         * unintentionally supplying multiple sequence elements.
         */
        if(event.type != InputTypeShort) {
            continue;
        }

        /* ------------------------------------------------------------------
         * Back / cancellation handling
         * ------------------------------------------------------------------ */

        /*
         * Back remains available during every state, including lockout.
         *
         * If authorized, Back explicitly returns the application to its
         * locked state. Otherwise it exits the application.
         */
        if(event.key == InputKeyBack) {
            if(app->unlocked) {
                app->unlocked = false;
                app->authorized_until = 0U;
                app->position = 0U;
                app->wrong_sequence = false;
            } else {
                running = false;
            }

            view_port_update(app->viewport);
            continue;
        }

        /* Ignore all other input while already authorized. */
        if(app->unlocked) {
            continue;
        }

        /*
         * Ignore authentication input during an active lockout.
         *
         * Back has already been handled above, so the user can always
         * leave the application.
         */
        if(is_locked_out(app)) {
            continue;
        }

        /* ------------------------------------------------------------------
         * Failed authentication acknowledgement
         * ------------------------------------------------------------------ */

        /*
         * After an incorrect sequence, require an explicit OK press before
         * accepting any new directional input. This prevents an accidental
         * button press from immediately beginning the next attempt.
         */
        if(app->wrong_sequence) {
            if(event.key == InputKeyOk) {
                app->wrong_sequence = false;
                app->position = 0U;
                view_port_update(app->viewport);
            }

            continue;
        }

        /* ------------------------------------------------------------------
         * Directional authentication
         * ------------------------------------------------------------------ */

        if(is_arrow(event.key)) {
            /*
             * Record whether each entered direction matches the expected
             * direction, but DO NOT reveal a mismatch before the complete
             * sequence has been entered.
             *
             * This prevents the UI from disclosing which position was wrong.
             */
            static bool sequence_valid = true;

            if(event.key != secret_sequence[app->position]) {
                sequence_valid = false;
            }

            app->position++;

            /*
             * Evaluate the attempt only after exactly SEQUENCE_LENGTH
             * directional inputs have been supplied.
             */
            if(app->position == SEQUENCE_LENGTH) {
                app->position = 0U;

                if(sequence_valid) {
                    app->unlocked = true;
                    app->failures = 0U;
                    save_failure_state(app->failures);

                    const uint32_t auth_ticks =
                        (AUTH_TIMEOUT_MS *
                         furi_kernel_get_tick_frequency()) /
                        1000U;

                    app->authorized_until =
                        furi_get_tick() + auth_ticks;
                } else {
                    app->wrong_sequence = true;

                    /* Saturate rather than allowing the counter to wrap. */
                    if(app->failures < UINT8_MAX) {
                        app->failures++;
                    }

                    /*
                     * Persist immediately so exiting or restarting the app
                     * cannot reset the consecutive-failure history.
                     */
                    save_failure_state(app->failures);

                    const uint32_t delay_ms =
                        get_lockout_delay(app->failures);

                    const uint32_t delay_ticks =
                        (delay_ms *
                         furi_kernel_get_tick_frequency()) /
                        1000U;

                    app->locked_until =
                        furi_get_tick() + delay_ticks;
                }

                /*
                 * Every new attempt starts with a clean validity state.
                 */
                sequence_valid = true;
            }

            view_port_update(app->viewport);
        }
    }

    /* ------------------------------------------------------------------
     * Cleanup
     * ------------------------------------------------------------------ */

    /*
     * Detach the viewport before releasing either the GUI record or the
     * viewport itself.
     */
    gui_remove_view_port(gui, app->viewport);
    furi_record_close(RECORD_GUI);

    view_port_free(app->viewport);
    furi_message_queue_free(app->input_queue);

    /*
     * Future versions containing cryptographic material should explicitly
     * zero sensitive buffers before they are released.
     */
    free(app);

    return 0;
}