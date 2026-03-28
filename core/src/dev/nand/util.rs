
pub fn parity(input: u8) -> u8 { 
    (input.count_ones() % 2) as u8 
}

pub fn calc_ecc(data: &mut [u8]) -> u32 {
    let mut a = [[0u8; 2]; 12];
    let mut a0 = 0u32;
    let mut a1 = 0u32;

    for (idx, byte) in data.iter().enumerate().take(512) {
        for j in 0..9 {
            a[3 + j][(idx >> j) & 1] ^= byte;
        }
    }

    let x: u8 = a[3][0] ^ a[3][1];
    a[0][0] = x & 0x55;
    a[0][1] = x & 0xaa;
    a[1][0] = x & 0x33;
    a[1][1] = x & 0xcc;
    a[2][0] = x & 0x0f;
    a[2][1] = x & 0xf0;

    for (idx, aj) in a.iter_mut().enumerate() {
        aj[0] = parity(aj[0]);
        aj[1] = parity(aj[1]);
        a0 |= (aj[0] as u32) << idx;
        a1 |= (aj[1] as u32) << idx;
    }


    (a0 & 0x0000_00ff) << 24 | (a0 & 0x0000_ff00) << 8 |
    (a1 & 0x0000_00ff) << 8  | (a1 & 0x0000_ff00) >> 8
}

