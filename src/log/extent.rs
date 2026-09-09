//! File extent descriptor and state representation.

pub use crate::extent_map::{
    Extent, Extent as ExtentState, Extent as SharedExtentState, StagedBuffer, ZERO_EXTENT_GENERATION,
    zero_extent_fields, zero_extent_len,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extent_trimming_is_independent() {
        let state = Extent::new_staged_buffer(vec![1, 2, 3, 4, 5], 0, 5);
        let mut clone = state.clone();

        clone.trim_left(2);
        match &clone {
            Extent::Staged {
                data,
                payload_offset,
                length,
            } => {
                assert_eq!(*payload_offset, 2);
                assert_eq!(*length, 3);
                assert_eq!(
                    &data.read().unwrap()[*payload_offset as usize..(*payload_offset + *length) as usize],
                    &[3, 4, 5]
                );
            }
            _ => panic!("expected Staged"),
        }
        match &state {
            Extent::Staged {
                data,
                payload_offset,
                length,
            } => {
                assert_eq!(*payload_offset, 0);
                assert_eq!(*length, 5);
                assert_eq!(&data.read().unwrap()[..], &[1, 2, 3, 4, 5]);
            }
            _ => panic!("expected Staged"),
        }

        clone.trim_right(2);
        match &clone {
            Extent::Staged {
                data,
                payload_offset,
                length,
            } => {
                assert_eq!(*payload_offset, 2);
                assert_eq!(*length, 2);
                assert_eq!(
                    &data.read().unwrap()[*payload_offset as usize..(*payload_offset + *length) as usize],
                    &[3, 4]
                );
            }
            _ => panic!("expected Staged"),
        }
        match &state {
            Extent::Staged {
                data,
                payload_offset,
                length,
            } => {
                assert_eq!(*payload_offset, 0);
                assert_eq!(*length, 5);
                assert_eq!(&data.read().unwrap()[..], &[1, 2, 3, 4, 5]);
            }
            _ => panic!("expected Staged"),
        }
    }
}
