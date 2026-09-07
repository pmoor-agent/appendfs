use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// Serializable error representation for sharing `io::Error`s across waiting follower threads.
#[derive(Clone, Debug)]
pub struct CoalesceError {
    pub kind: io::ErrorKind,
    pub message: String,
}

impl From<&io::Error> for CoalesceError {
    fn from(err: &io::Error) -> Self {
        Self {
            kind: err.kind(),
            message: err.to_string(),
        }
    }
}

impl From<CoalesceError> for io::Error {
    fn from(err: CoalesceError) -> Self {
        io::Error::new(err.kind, err.message)
    }
}

#[derive(Debug)]
enum CallState {
    InProgress,
    Done(Result<Arc<Vec<u8>>, CoalesceError>),
}

#[derive(Debug)]
struct InFlightCall {
    state: Mutex<CallState>,
    cond: Condvar,
}

impl InFlightCall {
    fn new() -> Self {
        Self {
            state: Mutex::new(CallState::InProgress),
            cond: Condvar::new(),
        }
    }
}

/// A panic-safe, synchronous single-flight deduplicator for concurrent remote reads.
///
/// When multiple concurrent threads request the same `(generation, block_idx)`, only the
/// first thread (the leader) issues the remote fetch. Concurrent follower threads wait on
/// a condition variable and share the resulting `Arc<Vec<u8>>` without issuing redundant
/// network requests or duplicate cache writes.
#[derive(Debug, Default)]
pub struct RemoteReadCoalescer {
    calls: Mutex<HashMap<(String, u64), Arc<InFlightCall>>>,
    coalesced_requests: AtomicU64,
    leader_requests: AtomicU64,
    in_flight_count: AtomicUsize,
}

/// A follower block reference representing an in-flight request initiated by another thread.
#[derive(Debug, Clone)]
pub struct FollowerBlock {
    pub block_idx: u64,
    call: Arc<InFlightCall>,
}

impl FollowerBlock {
    /// Awaits completion of the in-flight fetch by the leader thread and returns the result.
    pub fn wait(&self) -> io::Result<Arc<Vec<u8>>> {
        let mut state = self.call.state.lock().unwrap();
        loop {
            match *state {
                CallState::InProgress => {
                    state = self.call.cond.wait(state).unwrap();
                }
                CallState::Done(Ok(ref data)) => {
                    return Ok(Arc::clone(data));
                }
                CallState::Done(Err(ref err)) => {
                    return Err(io::Error::from(err.clone()));
                }
            }
        }
    }
}

/// RAII guard managing in-flight calls for which the current thread is the leader.
///
/// If dropped before completing, any uncompleted leader calls are marked with an
/// `Interrupted` error to ensure waiting followers never deadlock.
pub struct BatchLeaderGuard<'a> {
    coalescer: &'a RemoteReadCoalescer,
    file_stem: String,
    leaders: Vec<(u64, Arc<InFlightCall>)>,
    completed: Vec<bool>,
}

impl<'a> BatchLeaderGuard<'a> {
    /// Returns the block indices for which this thread is registered as the leader.
    pub fn leader_blocks(&self) -> Vec<u64> {
        self.leaders.iter().map(|(b, _)| *b).collect()
    }

    /// Completes the in-flight call for `block_idx` with a success or error result,
    /// notifying all waiting followers.
    pub fn complete(&mut self, block_idx: u64, result: Result<Arc<Vec<u8>>, &io::Error>) {
        if let Some(pos) = self.leaders.iter().position(|(b, _)| *b == block_idx)
            && !self.completed[pos]
        {
            self.completed[pos] = true;
            let (_, call) = &self.leaders[pos];
            {
                let mut state = call.state.lock().unwrap();
                match result {
                    Ok(ref data) => {
                        *state = CallState::Done(Ok(Arc::clone(data)));
                    }
                    Err(err) => {
                        *state = CallState::Done(Err(CoalesceError::from(err)));
                    }
                }
                call.cond.notify_all();
            }

            let mut calls = self.coalescer.calls.lock().unwrap();
            calls.remove(&(self.file_stem.clone(), block_idx));
            self.coalescer.in_flight_count.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for BatchLeaderGuard<'_> {
    fn drop(&mut self) {
        let mut calls_guard = None;
        for pos in 0..self.leaders.len() {
            if !self.completed[pos] {
                self.completed[pos] = true;
                let (block_idx, call) = &self.leaders[pos];
                {
                    let mut state = call.state.lock().unwrap();
                    *state = CallState::Done(Err(CoalesceError {
                        kind: io::ErrorKind::Interrupted,
                        message: "in-flight remote read aborted due to thread panic or early exit".to_string(),
                    }));
                    call.cond.notify_all();
                }

                let calls = calls_guard.get_or_insert_with(|| self.coalescer.calls.lock().unwrap());
                calls.remove(&(self.file_stem.clone(), *block_idx));
                self.coalescer.in_flight_count.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

impl RemoteReadCoalescer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of concurrent requests deduplicated (joined an existing in-flight fetch).
    pub fn coalesced_requests(&self) -> u64 {
        self.coalesced_requests.load(Ordering::SeqCst)
    }

    /// Number of requests that acted as leaders (initiated an actual fetch).
    pub fn leader_requests(&self) -> u64 {
        self.leader_requests.load(Ordering::SeqCst)
    }

    /// Total number of requests processed by this coalescer.
    pub fn total_requests(&self) -> u64 {
        self.leader_requests() + self.coalesced_requests()
    }

    /// Current number of distinct block fetches in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight_count.load(Ordering::SeqCst)
    }

    /// Registers a batch of requested block indices.
    ///
    /// Returns a [`BatchLeaderGuard`] managing the blocks for which this caller became the leader,
    /// and a list of [`FollowerBlock`]s for blocks already in flight by other concurrent threads.
    pub fn register_batch<'a>(&'a self, file_stem: &str, blocks: &[u64]) -> (BatchLeaderGuard<'a>, Vec<FollowerBlock>) {
        let stem = crate::remote::block_cache::clean_file_stem(file_stem);
        let mut calls = self.calls.lock().unwrap();
        let mut leaders = Vec::new();
        let mut followers = Vec::new();

        for &b in blocks {
            let key = (stem.to_string(), b);
            if let Some(existing) = calls.get(&key) {
                self.coalesced_requests.fetch_add(1, Ordering::SeqCst);
                followers.push(FollowerBlock {
                    block_idx: b,
                    call: Arc::clone(existing),
                });
            } else {
                self.leader_requests.fetch_add(1, Ordering::SeqCst);
                self.in_flight_count.fetch_add(1, Ordering::SeqCst);
                let call = Arc::new(InFlightCall::new());
                calls.insert(key, Arc::clone(&call));
                leaders.push((b, call));
            }
        }

        let num_leaders = leaders.len();
        let guard = BatchLeaderGuard {
            coalescer: self,
            file_stem: stem.to_string(),
            leaders,
            completed: vec![false; num_leaders],
        };

        (guard, followers)
    }

    /// Executes `fetch` for `(file_stem, block_idx)` if no fetch is currently in flight.
    /// If an identical fetch is already in flight, awaits its completion and shares the result.
    pub fn coalesce<F>(&self, file_stem: &str, block_idx: u64, fetch: F) -> io::Result<Arc<Vec<u8>>>
    where
        F: FnOnce() -> io::Result<Arc<Vec<u8>>>,
    {
        let (mut guard, followers) = self.register_batch(file_stem, &[block_idx]);
        if guard.leader_blocks().is_empty() {
            // Follower: wait for leader to complete the fetch
            followers[0].wait()
        } else {
            // Leader: initiate fetch and publish result
            let result = fetch();
            match result {
                Ok(ref data) => {
                    guard.complete(block_idx, Ok(Arc::clone(data)));
                    result
                }
                Err(ref err) => {
                    guard.complete(block_idx, Err(err));
                    result
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_singleflight_coalescing_concurrent_identical_requests() {
        let coalescer = Arc::new(RemoteReadCoalescer::new());
        let invocations = Arc::new(AtomicUsize::new(0));

        let num_threads = 10;
        let mut handles = Vec::new();

        for _ in 0..num_threads {
            let c = Arc::clone(&coalescer);
            let inv = Arc::clone(&invocations);
            handles.push(thread::spawn(move || {
                c.coalesce("000001", 0, || {
                    inv.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(50));
                    Ok(Arc::new(vec![42u8; 1024]))
                })
                .unwrap()
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            results.push(h.join().unwrap());
        }

        assert_eq!(
            invocations.load(Ordering::SeqCst),
            1,
            "fetch closure must be called only once"
        );
        assert_eq!(coalescer.leader_requests(), 1);
        assert_eq!(coalescer.coalesced_requests(), (num_threads - 1) as u64);
        assert_eq!(coalescer.total_requests(), num_threads as u64);
        assert_eq!(coalescer.in_flight(), 0);

        for res in results {
            assert_eq!(&res[..], &[42u8; 1024]);
        }
    }

    #[test]
    fn test_singleflight_independent_keys() {
        let coalescer = Arc::new(RemoteReadCoalescer::new());
        let inv1 = Arc::new(AtomicUsize::new(0));
        let inv2 = Arc::new(AtomicUsize::new(0));

        let c1 = Arc::clone(&coalescer);
        let i1 = Arc::clone(&inv1);
        let h1 = thread::spawn(move || {
            c1.coalesce("000001", 0, || {
                i1.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
                Ok(Arc::new(vec![1u8; 10]))
            })
            .unwrap()
        });

        let c2 = Arc::clone(&coalescer);
        let i2 = Arc::clone(&inv2);
        let h2 = thread::spawn(move || {
            c2.coalesce("000001", 1, || {
                i2.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
                Ok(Arc::new(vec![2u8; 10]))
            })
            .unwrap()
        });

        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        assert_eq!(&r1[..], &[1u8; 10]);
        assert_eq!(&r2[..], &[2u8; 10]);
        assert_eq!(inv1.load(Ordering::SeqCst), 1);
        assert_eq!(inv2.load(Ordering::SeqCst), 1);
        assert_eq!(coalescer.leader_requests(), 2);
        assert_eq!(coalescer.coalesced_requests(), 0);
    }

    #[test]
    fn test_singleflight_error_propagation() {
        let coalescer = Arc::new(RemoteReadCoalescer::new());
        let mut handles = Vec::new();

        for _ in 0..5 {
            let c = Arc::clone(&coalescer);
            handles.push(thread::spawn(move || {
                c.coalesce("000001", 0, || {
                    thread::sleep(Duration::from_millis(20));
                    Err(io::Error::new(io::ErrorKind::ConnectionReset, "network dropped"))
                })
            }));
        }

        for h in handles {
            let res = h.join().unwrap();
            assert!(res.is_err());
            let err = res.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
            assert!(err.to_string().contains("network dropped"));
        }

        assert_eq!(coalescer.leader_requests(), 1);
        assert_eq!(coalescer.coalesced_requests(), 4);
    }

    #[test]
    fn test_singleflight_panic_safety() {
        let coalescer = Arc::new(RemoteReadCoalescer::new());

        let c1 = Arc::clone(&coalescer);
        let h1 = thread::spawn(move || {
            c1.coalesce("000001", 0, || -> io::Result<Arc<Vec<u8>>> {
                thread::sleep(Duration::from_millis(20));
                panic!("leader thread simulated crash");
            })
        });

        let c2 = Arc::clone(&coalescer);
        let h2 = thread::spawn(move || {
            // Give leader thread a few millis to become leader
            thread::sleep(Duration::from_millis(5));
            c2.coalesce("000001", 0, || Ok(Arc::new(vec![0u8])))
        });

        // h1 panics
        assert!(h1.join().is_err());

        // h2 must not deadlock, but receive an Interrupted error
        let r2 = h2.join().unwrap();
        assert!(r2.is_err());
        assert_eq!(r2.unwrap_err().kind(), io::ErrorKind::Interrupted);

        assert_eq!(coalescer.in_flight(), 0);
    }

    #[test]
    fn test_batch_coalescing_partial_overlap() {
        let coalescer = Arc::new(RemoteReadCoalescer::new());

        // Thread 1 registers [1, 2, 3]
        let (mut guard1, followers1) = coalescer.register_batch("000001", &[1, 2, 3]);
        assert_eq!(guard1.leader_blocks(), vec![1, 2, 3]);
        assert!(followers1.is_empty());
        assert_eq!(coalescer.in_flight(), 3);

        // Thread 2 registers [2, 3, 4] while Thread 1 is in flight
        let (mut guard2, followers2) = coalescer.register_batch("000001", &[2, 3, 4]);
        assert_eq!(guard2.leader_blocks(), vec![4]);
        assert_eq!(followers2.len(), 2);
        assert_eq!(followers2[0].block_idx, 2);
        assert_eq!(followers2[1].block_idx, 3);
        assert_eq!(coalescer.in_flight(), 4);

        // Complete Thread 1's blocks
        guard1.complete(1, Ok(Arc::new(vec![10u8; 100])));
        guard1.complete(2, Ok(Arc::new(vec![20u8; 100])));
        guard1.complete(3, Ok(Arc::new(vec![30u8; 100])));

        // Followers in Thread 2 can now wait and get the data from Thread 1
        let res2 = followers2[0].wait().unwrap();
        let res3 = followers2[1].wait().unwrap();
        assert_eq!(&res2[..], &[20u8; 100]);
        assert_eq!(&res3[..], &[30u8; 100]);

        // Complete Thread 2's block 4
        guard2.complete(4, Ok(Arc::new(vec![40u8; 100])));

        assert_eq!(coalescer.in_flight(), 0);
        assert_eq!(coalescer.leader_requests(), 4);
        assert_eq!(coalescer.coalesced_requests(), 2);
    }
}
