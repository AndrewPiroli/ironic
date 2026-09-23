# A custom boot0 for Nintendo Wii emulation

This is a hand written custom boot0 for those who do not wish to dump or otherwise source a boot0.bin.

It is not intended to be a faithful reproduction nor is it ever intended to run on a real console or emulator other
than ironic. There is no debug printing or SHA verification done to the loaded boot1 image.
It does however support full ECC correction, so it should boot any nand image that boots on a Wii.

If you can find a nand image that does not work with this boot0, but does work with a real console dumped boot0,
please raise an issue on GitHub.

This is considered alpha software at the moment.
