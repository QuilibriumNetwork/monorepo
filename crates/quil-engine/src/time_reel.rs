/// Global time reel: coordinates frame scheduling and time synchronization
/// across the consensus network.
pub struct GlobalTimeReel {
    /// The current frame number at the head of the time reel.
    pub head_frame: u64,
    /// The timestamp of the head frame.
    pub head_timestamp: i64,
}

impl GlobalTimeReel {
    pub fn new() -> Self {
        Self {
            head_frame: 0,
            head_timestamp: 0,
        }
    }

    /// Advance the time reel to a new frame.
    pub fn advance(&mut self, frame_number: u64, timestamp: i64) {
        if frame_number > self.head_frame {
            self.head_frame = frame_number;
            self.head_timestamp = timestamp;
        }
    }
}

impl Default for GlobalTimeReel {
    fn default() -> Self {
        Self::new()
    }
}
