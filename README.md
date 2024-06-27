# ironic
Research emulator for the ARM9 core in the Nintendo Wii.

Credit is due to the following projects and resources that have guided the 
implementation since the beginning:

- [Team Twiizers' fork of Skyeye](https://github.com/marcan/skyeye-starlet)
- [MINI](https://github.com/fail0verflow/mini)
- [Wiibrew](https://wiibrew.org)
- [YAGCD](https://gc-forever.com/yagcd/)
- [libogc](https://github.com/devkitPro/libogc)
- [archshift/llama](https://github.com/archshift/llama)
- [MerryMage/dynarmic](https://github.com/MerryMage/dynarmic)
- All of the folks who still work on Wii/GC homebrew

## Quick Roadmap
- [x] Execution through the boot ROM
- [x] Execution through IOS first-stage bootloader
- [x] Execution through IOS second-stage bootloader
- [x] Execution in the IOS kernel
- [x] Broadway/PowerPC-world HLE 
- [x] Emulated SDHC (SD card) support. (Alpha quality ATM! Place sd image as "sd.img" to connect card)
- [ ] Emulated USB support?
- [ ] Emulated WLAN functionality?
- [ ] Write a bunch of tests
- [ ] Guest debugging functionality (perhaps via GDB, or some UI?)
- [ ] Go fast (performance optimizations, i.e. a JIT backend, etc)
- [ ] Tools for fuzzing guest code
- [ ] Other related tools?

ironic is primarily developed on Linux and macOS (x86-64 and AArch64).
Support for Windows is provided on best-effort basis. For technical reasons, minimum support is at Windows 10 1809 and Server 2019.


## Contributing
I am not interested in accepting contributions to this project and I will 
probably work on it alone; at least, for now. When I get around to deciding on 
a license, it will probably be as permissive as possible.

## Building
I use Nightly by default, so you may have to do something like this:
```
$ git clone https://github.com/eigenform/ironic && cd ironic/
...
$ rustup toolchain install nightly
$ rustup override set nightly
$ cargo build --release
```

## Usage
In order to boot, `ironic` expects the following files to live in the project 
directory:

- `boot0.bin` - The Wii boot ROM dumped from your console
- `nand.bin` - The NAND flash data dumped from your console
- `otp.bin` - The associated OTP/fused memory dumped from your console
- `seeprom.bin` - The associated SEEPROM memory dumped from your console

The included script `create_binfiles_from_nand.sh` will generate otp.bin and seeprom.bin for you using your nand.bin

You can run the emulator with the interpreter backend like this:
```
$ cargo run --release
```

Like `skyeye-starlet`, the `ironic-tui` target includes a server for PPC HLE.
Tools for interacting with the server and representing processes on the 
PowerPC-side of the machine can be found in [`pyronic/`](pyronic/).

