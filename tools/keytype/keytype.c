// Type stdin into the focused Wayland window with the normal US layout.
// wtype builds a layout from the text it types, and 1Password dropped characters
// from it. This sends the key presses a US keyboard sends.
// Usage matches the part of wtype that keyhole runs:
//   keytype -            type stdin, without a trailing newline
//   keytype -k Return    press Enter
// Text with anything but printable ASCII is refused before a key is pressed.

#define _GNU_SOURCE
#include <errno.h>
#include <linux/input-event-codes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include <xkbcommon/xkbcommon.h>

#include "virtual-keyboard-unstable-v1-client-protocol.h"

#define MAX_TEXT 4096
#define SHIFT_MASK 1u
#define KEY_GAP_MS 2

struct stroke {
    unsigned code;
    bool shift;
};

static struct wl_seat *seat;
static struct zwp_virtual_keyboard_manager_v1 *manager;

static const unsigned digit_codes[10] = {KEY_0, KEY_1, KEY_2, KEY_3, KEY_4,
                                         KEY_5, KEY_6, KEY_7, KEY_8, KEY_9};
// A to Z, in order.
static const unsigned letter_codes[26] = {
    KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F, KEY_G, KEY_H, KEY_I,
    KEY_J, KEY_K, KEY_L, KEY_M, KEY_N, KEY_O, KEY_P, KEY_Q, KEY_R,
    KEY_S, KEY_T, KEY_U, KEY_V, KEY_W, KEY_X, KEY_Y, KEY_Z};

static bool stroke_for(unsigned char c, struct stroke *out) {
    static const struct {
        char c;
        unsigned code;
        bool shift;
    } symbols[] = {
        {' ', KEY_SPACE, false},       {'!', KEY_1, true},
        {'"', KEY_APOSTROPHE, true},   {'#', KEY_3, true},
        {'$', KEY_4, true},            {'%', KEY_5, true},
        {'&', KEY_7, true},            {'\'', KEY_APOSTROPHE, false},
        {'(', KEY_9, true},            {')', KEY_0, true},
        {'*', KEY_8, true},            {'+', KEY_EQUAL, true},
        {',', KEY_COMMA, false},       {'-', KEY_MINUS, false},
        {'.', KEY_DOT, false},         {'/', KEY_SLASH, false},
        {':', KEY_SEMICOLON, true},    {';', KEY_SEMICOLON, false},
        {'<', KEY_COMMA, true},        {'=', KEY_EQUAL, false},
        {'>', KEY_DOT, true},          {'?', KEY_SLASH, true},
        {'@', KEY_2, true},            {'[', KEY_LEFTBRACE, false},
        {'\\', KEY_BACKSLASH, false},  {']', KEY_RIGHTBRACE, false},
        {'^', KEY_6, true},            {'_', KEY_MINUS, true},
        {'`', KEY_GRAVE, false},       {'{', KEY_LEFTBRACE, true},
        {'|', KEY_BACKSLASH, true},    {'}', KEY_RIGHTBRACE, true},
        {'~', KEY_GRAVE, true},
    };
    if (c >= 'a' && c <= 'z') {
        *out = (struct stroke){letter_codes[c - 'a'], false};
        return true;
    }
    if (c >= 'A' && c <= 'Z') {
        *out = (struct stroke){letter_codes[c - 'A'], true};
        return true;
    }
    if (c >= '0' && c <= '9') {
        *out = (struct stroke){digit_codes[c - '0'], false};
        return true;
    }
    for (size_t i = 0; i < sizeof symbols / sizeof symbols[0]; i++) {
        if ((unsigned char)symbols[i].c == c) {
            *out = (struct stroke){symbols[i].code, symbols[i].shift};
            return true;
        }
    }
    return false;
}

static void on_global(void *data, struct wl_registry *registry, uint32_t name,
                      const char *interface, uint32_t version) {
    (void)data;
    (void)version;
    if (strcmp(interface, wl_seat_interface.name) == 0 && !seat) {
        seat = wl_registry_bind(registry, name, &wl_seat_interface, 1);
    } else if (strcmp(interface, zwp_virtual_keyboard_manager_v1_interface.name) == 0) {
        manager = wl_registry_bind(registry, name,
                                   &zwp_virtual_keyboard_manager_v1_interface, 1);
    }
}

static void on_global_remove(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data;
    (void)registry;
    (void)name;
}

static const struct wl_registry_listener registry_listener = {on_global, on_global_remove};

static void pause_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) == -1 && errno == EINTR) {
    }
}

static uint32_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint32_t)(t.tv_sec * 1000 + t.tv_nsec / 1000000);
}

static bool send_us_layout(struct zwp_virtual_keyboard_v1 *keyboard) {
    struct xkb_context *context = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    if (!context) return false;
    struct xkb_rule_names names = {.rules = "evdev", .model = "pc105", .layout = "us"};
    struct xkb_keymap *keymap =
        xkb_keymap_new_from_names(context, &names, XKB_KEYMAP_COMPILE_NO_FLAGS);
    if (!keymap) {
        xkb_context_unref(context);
        return false;
    }
    char *text = xkb_keymap_get_as_string(keymap, XKB_KEYMAP_FORMAT_TEXT_V1);
    size_t size = text ? strlen(text) + 1 : 0;
    int fd = text ? memfd_create("keytype-keymap", MFD_CLOEXEC) : -1;
    bool sent = fd >= 0 && write(fd, text, size) == (ssize_t)size;
    if (sent) {
        zwp_virtual_keyboard_v1_keymap(keyboard, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, fd,
                                       (uint32_t)size);
    }
    if (fd >= 0) close(fd);
    free(text);
    xkb_keymap_unref(keymap);
    xkb_context_unref(context);
    return sent;
}

static void press(struct wl_display *display, struct zwp_virtual_keyboard_v1 *keyboard,
                  struct stroke s) {
    if (s.shift) {
        zwp_virtual_keyboard_v1_key(keyboard, now_ms(), KEY_LEFTSHIFT,
                                    WL_KEYBOARD_KEY_STATE_PRESSED);
        zwp_virtual_keyboard_v1_modifiers(keyboard, SHIFT_MASK, 0, 0, 0);
        wl_display_flush(display);
        pause_ms(KEY_GAP_MS);
    }
    zwp_virtual_keyboard_v1_key(keyboard, now_ms(), s.code, WL_KEYBOARD_KEY_STATE_PRESSED);
    wl_display_flush(display);
    pause_ms(KEY_GAP_MS);
    zwp_virtual_keyboard_v1_key(keyboard, now_ms(), s.code, WL_KEYBOARD_KEY_STATE_RELEASED);
    wl_display_flush(display);
    pause_ms(KEY_GAP_MS);
    if (s.shift) {
        zwp_virtual_keyboard_v1_key(keyboard, now_ms(), KEY_LEFTSHIFT,
                                    WL_KEYBOARD_KEY_STATE_RELEASED);
        zwp_virtual_keyboard_v1_modifiers(keyboard, 0, 0, 0, 0);
        wl_display_flush(display);
        pause_ms(KEY_GAP_MS);
    }
}

static int run(const unsigned char *text, size_t length, bool enter) {
    struct wl_display *display = wl_display_connect(NULL);
    if (!display) {
        fputs("keytype: no Wayland display\n", stderr);
        return 1;
    }
    struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &registry_listener, NULL);
    wl_display_roundtrip(display);
    if (!seat || !manager) {
        fputs("keytype: the compositor offers no virtual keyboard\n", stderr);
        wl_display_disconnect(display);
        return 1;
    }
    struct zwp_virtual_keyboard_v1 *keyboard =
        zwp_virtual_keyboard_manager_v1_create_virtual_keyboard(manager, seat);
    if (!send_us_layout(keyboard)) {
        fputs("keytype: could not build the US layout\n", stderr);
        wl_display_disconnect(display);
        return 1;
    }
    wl_display_roundtrip(display);
    pause_ms(50);

    for (size_t i = 0; i < length; i++) {
        struct stroke s;
        stroke_for(text[i], &s);
        press(display, keyboard, s);
    }
    if (enter) press(display, keyboard, (struct stroke){KEY_ENTER, false});

    int failed = wl_display_roundtrip(display) < 0;
    zwp_virtual_keyboard_v1_destroy(keyboard);
    wl_display_roundtrip(display);
    wl_display_disconnect(display);
    if (failed) fputs("keytype: lost the Wayland connection\n", stderr);
    return failed;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "-k") == 0 && strcmp(argv[2], "Return") == 0) {
        return run(NULL, 0, true);
    }
    if (argc != 2 || strcmp(argv[1], "-") != 0) {
        fputs("usage: keytype - | keytype -k Return\n", stderr);
        return 2;
    }

    static unsigned char text[MAX_TEXT];
    mlock(text, sizeof text);
    size_t length = 0;
    for (;;) {
        ssize_t got = read(STDIN_FILENO, text + length, sizeof text - length);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) {
            explicit_bzero(text, sizeof text);
            fputs("keytype: could not read the text\n", stderr);
            return 1;
        }
        if (got == 0) break;
        length += (size_t)got;
        if (length == sizeof text) {
            explicit_bzero(text, sizeof text);
            fputs("keytype: text is too long\n", stderr);
            return 1;
        }
    }
    for (size_t i = 0; i < length; i++) {
        struct stroke s;
        if (!stroke_for(text[i], &s)) {
            explicit_bzero(text, sizeof text);
            fputs("keytype: the text has a character a US keyboard cannot type. Nothing was typed.\n",
                  stderr);
            return 1;
        }
    }
    int result = run(text, length, false);
    explicit_bzero(text, sizeof text);
    return result;
}
