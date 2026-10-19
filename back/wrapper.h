/*
 * Wrapper header for bindgen.
 *
 * Exposes the public libppcemu API to Rust. This is the emulator library
 * that the (formerly out-of-process) `cronic` helper links against; the
 * helper's IPC logic is being reimplemented directly as a backend thread.
 */

#include <ppcemu/ppcemu.h>
