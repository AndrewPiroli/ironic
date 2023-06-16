# rust-elf2
A fork of the `elf` crate, rolled back to 0.0.12 and updated from there.

The package name has been changed to elf2 to avoid conflicts if I ever publish to crates.io

If you are already using elf 0.0.X you can update seamlessly with cargo's package renaming feature

Change your Cargo.toml from

`elf = "..."`

to

`elf = { package = "elf2", path = "/path/to/rust-elf2" }`
