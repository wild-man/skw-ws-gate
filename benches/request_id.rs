//! Request-id strategies of `dispatch_request` / `dispatch_back_message`, outside the gate
//! (it is a bin crate, so its types can't be imported here):
//!
//! - `strings4` — before fix E: the parsed `Signature` is copied into the registry key, the
//!   entry's `reply_id`, the watchdog's copy and a temporary (4 copies)
//! - `string_moved` — the cheapest `String` version: the parsed `Signature` is moved in as the
//!   key, the reply goes out under the key `remove()` hands back, only the watchdog copies it
//! - `arc` — fix E as applied: one `Arc<str>` shared by key, `reply_id` and watchdog
//!
//! Each request: dispatch (frame thread), a provisional reply (`get`, the entry stays) and the
//! final reply (`remove`), then the watchdog drops its copy. Run: `cargo bench -p ws --bench request_id`.

use std::{
    alloc::{GlobalAlloc, Layout},
    borrow::Borrow,
    hash::Hash,
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

use criterion::Criterion;
use dashmap::DashMap;
use mimalloc::MiMalloc;

/// mimalloc (the gate's allocator) plus allocation counters, active only while `COUNTING`
struct Counting;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            LIVE_BYTES.fetch_add(layout.size() as isize, Relaxed);
        }
        unsafe { MiMalloc.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if COUNTING.load(Relaxed) {
            LIVE_BYTES.fetch_sub(layout.size() as isize, Relaxed);
        }
        unsafe { MiMalloc.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Relaxed) {
            ALLOCS.fetch_add(1, Relaxed);
            LIVE_BYTES.fetch_add(new_size as isize - layout.size() as isize, Relaxed);
        }
        unsafe { MiMalloc.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// an ed25519 signature in base64: 64 bytes -> 88 chars, capacity exactly 88 like a parsed one
fn signature(i: usize) -> String {
    format!("{:0>88}", i).into_boxed_str().into_string()
}

trait Ids {
    const NAME: &'static str;
    type Key: Eq + Hash + Borrow<str> + Send + Sync;
    type Entry: Send + Sync;
    type Watch: Send;
    type Reply: AsRef<str> + Send;

    /// frame thread: takes the parsed `Signature`, returns the watchdog's copy
    fn dispatch(map: &DashMap<Self::Key, Self::Entry>, parsed: String) -> Self::Watch;
    /// back receiver: provisional reply, the entry stays
    fn provisional(map: &DashMap<Self::Key, Self::Entry>, sig: &str) -> Option<Self::Reply>;
    /// back receiver: final reply, the entry goes
    fn final_reply(map: &DashMap<Self::Key, Self::Entry>, sig: &str) -> Option<Self::Reply>;
}

struct Strings4;
impl Ids for Strings4 {
    const NAME: &'static str = "strings4";
    type Key = String;
    type Entry = String;
    type Watch = String;
    type Reply = String;

    fn dispatch(map: &DashMap<String, String>, parsed: String) -> String {
        let signature = parsed.clone(); // `let signature = req.signature.clone()`
        let key = signature.to_string(); // `entry(signature.to_string())`
        let reply_id = parsed.clone(); // `reply_id: req.signature.clone()`
        let watch = signature.to_string(); // `signature_for_timeout`
        map.insert(key, reply_id);
        watch
    }

    fn provisional(map: &DashMap<String, String>, sig: &str) -> Option<String> {
        map.get(sig).map(|e| e.value().clone())
    }

    fn final_reply(map: &DashMap<String, String>, sig: &str) -> Option<String> {
        map.remove(sig).map(|(_, reply_id)| reply_id)
    }
}

struct StringMoved;
impl Ids for StringMoved {
    const NAME: &'static str = "string_moved";
    type Key = String;
    /// `reply_id`, `None` = the key itself (signed requests)
    type Entry = Option<String>;
    type Watch = String;
    type Reply = String;

    fn dispatch(map: &DashMap<String, Option<String>>, parsed: String) -> String {
        let watch = parsed.clone();
        map.insert(parsed, None);
        watch
    }

    fn provisional(map: &DashMap<String, Option<String>>, sig: &str) -> Option<String> {
        map.get(sig)
            .map(|e| e.value().clone().unwrap_or_else(|| e.key().clone()))
    }

    fn final_reply(map: &DashMap<String, Option<String>>, sig: &str) -> Option<String> {
        map.remove(sig)
            .map(|(key, reply_id)| reply_id.unwrap_or(key))
    }
}

struct ArcStr;
impl Ids for ArcStr {
    const NAME: &'static str = "arc";
    type Key = Arc<str>;
    type Entry = Arc<str>;
    type Watch = Arc<str>;
    type Reply = Arc<str>;

    fn dispatch(map: &DashMap<Arc<str>, Arc<str>>, parsed: String) -> Arc<str> {
        let reply_id: Arc<str> = parsed.into();
        let key = reply_id.clone();
        let watch = key.clone();
        map.insert(key, reply_id);
        watch
    }

    fn provisional(map: &DashMap<Arc<str>, Arc<str>>, sig: &str) -> Option<Arc<str>> {
        map.get(sig).map(|e| e.value().clone())
    }

    fn final_reply(map: &DashMap<Arc<str>, Arc<str>>, sig: &str) -> Option<Arc<str>> {
        map.remove(sig).map(|(_, reply_id)| reply_id)
    }
}

/// one request on one thread: the parsed `Signature` is allocated here, as the frame parse does
fn one_request<V: Ids>(map: &DashMap<V::Key, V::Entry>, sig: &str, provisional: bool) {
    let watch = V::dispatch(map, sig.to_owned());
    if provisional {
        black_box(V::provisional(map, sig).as_ref().map(AsRef::as_ref));
    }
    black_box(V::final_reply(map, sig).as_ref().map(AsRef::as_ref));
    drop(watch);
}

/// `n` requests the way the gate spreads them: dispatched on a frame worker, replied on the
/// back receiver, watchdog copies dropped on a third thread (so frees cross threads)
fn cross_thread<V: Ids>(n: usize) -> Duration
where
    V::Key: 'static,
    V::Entry: 'static,
{
    let parsed: Vec<String> = (0..n).map(signature).collect();
    let headers = parsed.clone();
    let map: DashMap<V::Key, V::Entry> = DashMap::with_capacity(n);
    let mut watches = Vec::with_capacity(n);

    let start = Instant::now();
    std::thread::scope(|s| {
        s.spawn(|| {
            for p in parsed {
                watches.push(V::dispatch(&map, p));
            }
        });
    });
    std::thread::scope(|s| {
        s.spawn(|| {
            for h in &headers {
                black_box(V::provisional(&map, h).as_ref().map(AsRef::as_ref));
                black_box(V::final_reply(&map, h).as_ref().map(AsRef::as_ref));
            }
        });
    });
    std::thread::scope(|s| {
        s.spawn(|| drop(watches));
    });
    start.elapsed()
}

/// allocations per request and heap held per pending request (while it waits for its reply)
fn report<V: Ids>() {
    const N: usize = 100_000;
    let map: DashMap<V::Key, V::Entry> = DashMap::with_capacity(N);
    let parsed: Vec<String> = (0..N).map(signature).collect();
    let headers = parsed.clone();
    let mut watches = Vec::with_capacity(N);

    ALLOCS.store(0, Relaxed);
    LIVE_BYTES.store(0, Relaxed);
    COUNTING.store(true, Relaxed);
    let parsed_bytes: isize = parsed.iter().map(|p| p.capacity() as isize).sum();
    // `by_ref`: the Vec's own buffer is freed after counting, not inside it
    let mut parsed = parsed.into_iter();
    for p in parsed.by_ref() {
        watches.push(V::dispatch(&map, p));
    }
    // the parsed strings were allocated before counting: bytes still held by them count too
    let held = LIVE_BYTES.load(Relaxed) + parsed_bytes;
    for h in &headers {
        drop(V::provisional(&map, h));
        drop(V::final_reply(&map, h));
    }
    drop(watches);
    COUNTING.store(false, Relaxed);
    drop(parsed);

    println!(
        "{:<13} allocs/request (dispatch + provisional + final, parse excluded): {:.2}   id bytes held per pending request: {:>4}",
        V::NAME,
        ALLOCS.load(Relaxed) as f64 / N as f64,
        held / N as isize,
    );
}

fn benches(c: &mut Criterion) {
    const SIG: &str = "Rk9PQkFSQkFaUVVYRk9PQkFSQkFaUVVYRk9PQkFSQkFaUVVYRk9PQkFSQkFaUVVYRk9PQkFSQkFaUVVYRk9PQg==";

    for provisional in [false, true] {
        let mut g = c.benchmark_group(if provisional {
            "one_thread/provisional+final"
        } else {
            "one_thread/final"
        });
        macro_rules! one {
            ($v:ty) => {{
                let map: DashMap<<$v as Ids>::Key, <$v as Ids>::Entry> = DashMap::with_capacity(16);
                g.bench_function(<$v as Ids>::NAME, |b| {
                    b.iter(|| one_request::<$v>(&map, SIG, provisional))
                });
            }};
        }
        one!(Strings4);
        one!(StringMoved);
        one!(ArcStr);
        g.finish();
    }

    let mut g = c.benchmark_group("cross_thread/provisional+final");
    g.bench_function(Strings4::NAME, |b| {
        b.iter_custom(|n| cross_thread::<Strings4>(n as usize))
    });
    g.bench_function(StringMoved::NAME, |b| {
        b.iter_custom(|n| cross_thread::<StringMoved>(n as usize))
    });
    g.bench_function(ArcStr::NAME, |b| {
        b.iter_custom(|n| cross_thread::<ArcStr>(n as usize))
    });
    g.finish();
}

fn main() {
    report::<Strings4>();
    report::<StringMoved>();
    report::<ArcStr>();

    let mut c = Criterion::default().configure_from_args();
    benches(&mut c);
    c.final_summary();
}
