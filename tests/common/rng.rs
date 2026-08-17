/// Shared deterministic 64-bit xorshift PRNG for repeatable test permutations.
#[allow(dead_code)]
pub struct TestRng {
    state: u64,
}

#[allow(dead_code)]
impl TestRng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x123456789ABCDEF0 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Generates a random usize in the range `[min, max]` (inclusive).
    pub fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + (self.next_u64() as usize % (max - min + 1))
    }

    /// Fills a buffer with pseudo-random bytes.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let val = self.next_u64().to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&val[..len]);
        }
    }
}
