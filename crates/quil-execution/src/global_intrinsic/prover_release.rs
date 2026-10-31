//! A prover's release in its epoch confirmation, and the release a committee
//! session requires of its members.
//!
//! Provers on a release that cannot follow GLOBAL stay allocated and keep
//! their committee seats, so every app committee they sit on stalls without
//! a trace in committed state. From [`confirm_release_frame`] a
//! [`ProverConfirm`] signs the release of the build that sent it and GLOBAL
//! records it on each confirmed allocation (`Release`). The release
//! eligibility schedule ([`MAINNET_RELEASE_ELIGIBILITY`]) lists
//! `(frame, minimum)` steps: a session GLOBAL forms at frame N
//! (`handoff::schedule::desired_members`) seats only allocations whose
//! recorded release is at least the minimum of the last step at or before N
//! ([`minimum_release_at`]); before the first step nothing is gated.
//! Committee eligibility, splits, merges and reassignment never read it.
//!
//! The release frame and every schedule step are consensus-affecting flag
//! days: an older build verifies a confirm that signs its release against the
//! legacy message and refuses it, records no releases, and forms sessions by
//! the steps it carries. Raising the minimum is therefore a new step at a
//! future frame that every GLOBAL-materializing build must carry before it,
//! never a change to a build's constants. Neither is scheduled on mainnet.
//!
//! Below the release frame a confirm's release bytes are ignored entirely:
//! not decoded (so a confirm re-encodes as an older build re-encodes it), not
//! signed, not verified and not recorded, as an older build ignores them, so
//! one early sender cannot split the builds.
//!
//! Trust model: a recorded release is authenticated (the prover's own key
//! signs it, so nobody can set another prover's release) but self-attested
//! (a modified build can claim any release). The schedule removes honest but
//! outdated provers; a false claim gains a prover nothing it would not have
//! as an eligible member anyway.

use super::prover_ops::ProverConfirm;
use crate::global_schema::{read_field, write_field};

/// A build's release: `version.patch.subpatch`, ordered in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Release {
    /// Major, minor and patch version (`quil_config::VERSION`).
    pub version: [u8; 3],
    /// The patch number (`quil_config::PATCH_NUMBER`).
    pub patch: u8,
    /// The subpatch counter (`quil_config::SUBPATCH_NUMBER`).
    pub subpatch: u16,
}

impl Release {
    /// Canonical encoding length: version, patch, subpatch (big-endian).
    pub const ENCODED_LEN: usize = 6;

    /// This build's release.
    pub const fn current() -> Self {
        Self {
            version: quil_config::VERSION,
            patch: quil_config::PATCH_NUMBER,
            subpatch: quil_config::SUBPATCH_NUMBER,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let [a, b, c] = self.version;
        let [s0, s1] = self.subpatch.to_be_bytes();
        [a, b, c, self.patch, s0, s1]
    }

    /// The release encoded in `bytes`, which must be exactly
    /// [`Self::ENCODED_LEN`] long.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let [a, b, c, patch, s0, s1] = <[u8; Self::ENCODED_LEN]>::try_from(bytes).ok()?;
        Some(Self {
            version: [a, b, c],
            patch,
            subpatch: u16::from_be_bytes([s0, s1]),
        })
    }
}

impl std::fmt::Display for Release {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [major, minor, patch_version] = self.version;
        write!(
            f,
            "{major}.{minor}.{patch_version}.{}.{}",
            self.patch, self.subpatch
        )
    }
}

impl std::str::FromStr for Release {
    type Err = String;

    /// `major.minor.patch.patch_number.subpatch`, as [`Release`] displays.
    fn from_str(text: &str) -> Result<Self, String> {
        let invalid = || format!("release {text:?} is not major.minor.patch.patch_number.subpatch");
        let parts: Vec<&str> = text.split('.').collect();
        let [major, minor, patch_version, patch, subpatch] = parts.as_slice() else {
            return Err(invalid());
        };
        let byte = |part: &str| part.parse::<u8>().map_err(|_| invalid());
        Ok(Self {
            version: [byte(major)?, byte(minor)?, byte(patch_version)?],
            patch: byte(patch)?,
            subpatch: subpatch.parse().map_err(|_| invalid())?,
        })
    }
}

/// One step of the release eligibility schedule: sessions formed from GLOBAL
/// frame `from_frame` seat only allocations that recorded `minimum` or later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseMinimum {
    pub from_frame: u64,
    pub minimum: Release,
}

/// From this GLOBAL frame a confirm signs and GLOBAL records its sender's
/// release (see the module documentation). Not scheduled on mainnet;
/// `QUIL_CONFIRM_RELEASE_FRAME` elsewhere, never by default.
pub const MAINNET_CONFIRM_RELEASE_FRAME: Option<u64> = None;

/// The mainnet release eligibility schedule, in strictly ascending frames.
/// Add a step only once confirms carry releases
/// ([`MAINNET_CONFIRM_RELEASE_FRAME`]) and the share of active allocations
/// that would lose their seats is measured; each step is a flag day. Empty:
/// nothing is gated. Elsewhere `QUIL_RELEASE_ELIGIBILITY`
/// (`frame=major.minor.patch.patch_number.subpatch,...`), never by default.
pub const MAINNET_RELEASE_ELIGIBILITY: &[ReleaseMinimum] = &[];

const CONFIRM_RELEASE_ENV: &str = "QUIL_CONFIRM_RELEASE_FRAME";
const RELEASE_ELIGIBILITY_ENV: &str = "QUIL_RELEASE_ELIGIBILITY";

static CONFIRM_RELEASE_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
static RELEASE_ELIGIBILITY: std::sync::OnceLock<Vec<ReleaseMinimum>> = std::sync::OnceLock::new();

thread_local! {
    static CONFIRM_RELEASE_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static RELEASE_ELIGIBILITY_OVERRIDE: std::cell::RefCell<Option<Vec<ReleaseMinimum>>> =
        const { std::cell::RefCell::new(None) };
}

fn frame_for(mainnet: Option<u64>, network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return mainnet.unwrap_or(u64::MAX);
    }
    setting
        .and_then(|value| value.parse().ok())
        .unwrap_or(u64::MAX)
}

/// Fix this process's confirm release frame from its network, and return it.
/// Called at startup before any frame is processed; the first call decides.
pub fn init_confirm_release_frame(network: u8) -> u64 {
    *CONFIRM_RELEASE_FRAME.get_or_init(|| {
        frame_for(
            MAINNET_CONFIRM_RELEASE_FRAME,
            network,
            std::env::var(CONFIRM_RELEASE_ENV).ok().as_deref(),
        )
    })
}

/// The confirm release frame [`init_confirm_release_frame`] fixed; without
/// it (qclient and other tools) the mainnet frame, whatever the environment
/// says, so a process never reads a setting its network ignores.
pub fn confirm_release_frame() -> u64 {
    if let Some(frame) = CONFIRM_RELEASE_OVERRIDE.with(|cell| cell.get()) {
        return frame;
    }
    CONFIRM_RELEASE_FRAME
        .get()
        .copied()
        .unwrap_or_else(|| MAINNET_CONFIRM_RELEASE_FRAME.unwrap_or(u64::MAX))
}

/// Set the confirm release frame for the calling thread only (tests).
pub fn set_confirm_release_frame_for_thread(frame: Option<u64>) {
    CONFIRM_RELEASE_OVERRIDE.with(|cell| cell.set(frame));
}

/// A schedule's steps must name strictly ascending frames, so the step in
/// force at a frame is unambiguous.
pub fn validate_schedule(schedule: &[ReleaseMinimum]) -> Result<(), String> {
    match schedule
        .windows(2)
        .find(|pair| pair[0].from_frame >= pair[1].from_frame)
    {
        Some(pair) => Err(format!(
            "release eligibility steps must be in strictly ascending frames: {} is not after {}",
            pair[1].from_frame, pair[0].from_frame
        )),
        None => Ok(()),
    }
}

/// Parse `frame=release,...` (empty: no steps) and validate it.
pub fn parse_schedule(text: &str) -> Result<Vec<ReleaseMinimum>, String> {
    let schedule =
        text.split(',')
            .map(str::trim)
            .filter(|step| !step.is_empty())
            .map(|step| {
                let (frame, minimum) = step.split_once('=').ok_or_else(|| {
                    format!("release eligibility step {step:?} is not frame=release")
                })?;
                Ok(ReleaseMinimum {
                    from_frame: frame.trim().parse().map_err(|_| {
                        format!("release eligibility frame {frame:?} is not a number")
                    })?,
                    minimum: minimum.trim().parse()?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
    validate_schedule(&schedule)?;
    Ok(schedule)
}

fn schedule_for(network: u8, setting: Option<&str>) -> Result<Vec<ReleaseMinimum>, String> {
    if network == 0 {
        validate_schedule(MAINNET_RELEASE_ELIGIBILITY)?;
        return Ok(MAINNET_RELEASE_ELIGIBILITY.to_vec());
    }
    setting.map_or_else(|| Ok(Vec::new()), parse_schedule)
}

/// Fix this process's release eligibility schedule from its network, and
/// return it. Called at startup before any frame is processed; the first
/// call decides. A setting that does not parse, or whose frames are not
/// strictly ascending, is an error: the node must not form sessions by
/// another schedule than its peers.
pub fn init_release_eligibility(network: u8) -> Result<&'static [ReleaseMinimum], String> {
    if let Some(schedule) = RELEASE_ELIGIBILITY.get() {
        return Ok(schedule);
    }
    let schedule = schedule_for(
        network,
        std::env::var(RELEASE_ELIGIBILITY_ENV).ok().as_deref(),
    )?;
    Ok(RELEASE_ELIGIBILITY.get_or_init(|| schedule))
}

/// The schedule [`init_release_eligibility`] fixed; without it the mainnet
/// schedule, whatever the environment says.
fn process_schedule() -> &'static [ReleaseMinimum] {
    RELEASE_ELIGIBILITY
        .get()
        .map_or(MAINNET_RELEASE_ELIGIBILITY, Vec::as_slice)
}

/// The minimum release a session formed at GLOBAL `frame` requires of its
/// members: that of the last schedule step at or before `frame`; none
/// before the first step.
pub fn minimum_release_at(frame: u64) -> Option<Release> {
    let at = |schedule: &[ReleaseMinimum]| {
        schedule
            .iter()
            .take_while(|step| step.from_frame <= frame)
            .last()
            .map(|step| step.minimum)
    };
    RELEASE_ELIGIBILITY_OVERRIDE
        .with(|cell| cell.borrow().as_deref().map(at))
        .unwrap_or_else(|| at(process_schedule()))
}

/// Set the release eligibility schedule for the calling thread only (tests);
/// `None` restores the process schedule.
pub fn set_release_eligibility_for_thread(
    schedule: Option<Vec<ReleaseMinimum>>,
) -> Result<(), String> {
    if let Some(schedule) = schedule.as_deref() {
        validate_schedule(schedule)?;
    }
    RELEASE_ELIGIBILITY_OVERRIDE.with(|cell| *cell.borrow_mut() = schedule);
    Ok(())
}

/// The release a confirm signed at `frame_number` carries: this build's from
/// [`confirm_release_frame`], none before it.
pub fn release_for_confirm(frame_number: u64) -> Option<Release> {
    (frame_number >= confirm_release_frame()).then(Release::current)
}

/// The release a confirm signed at `frame_number` binds into its signing
/// message: `release` from [`confirm_release_frame`], none before it.
pub fn signed_release(frame_number: u64, release: Option<&Release>) -> Option<&Release> {
    release.filter(|_| frame_number >= confirm_release_frame())
}

/// The release a confirm carries in effect: its signed frame (not the frame
/// that includes it) decides, so every node reads the same confirm alike.
pub fn confirmed_release(op: &ProverConfirm) -> Option<Release> {
    signed_release(op.frame_number, op.release.as_ref()).copied()
}

/// Whether an allocation with `recorded` release may be seated in a session
/// formed at GLOBAL `frame`, by [`minimum_release_at`]. While a step applies
/// it fails closed: an allocation whose confirms never recorded a release (an
/// older build's, one before the release frame, or one sent without a
/// release) is not. The release is authenticated but self-attested (see the
/// module documentation).
pub fn seat_eligible(recorded: Option<&Release>, frame: u64) -> bool {
    minimum_release_at(frame)
        .is_none_or(|minimum| recorded.is_some_and(|release| *release >= minimum))
}

const ALLOCATION: &str = "allocation:ProverAllocation";

/// The release recorded on an allocation vertex tree.
pub fn read_release(allocation: &quil_tries::VectorCommitmentTree) -> Option<Release> {
    Release::from_bytes(&read_field(allocation, ALLOCATION, "Release")?)
}

/// Record `release` on an allocation vertex tree.
pub fn write_release(
    allocation: &mut quil_tries::VectorCommitmentTree,
    release: &Release,
) -> quil_types::error::Result<()> {
    write_field(allocation, ALLOCATION, "Release", &release.to_bytes())
}

/// The release committed GLOBAL state records for the allocation of the
/// prover with `public_key` on `filter`; `None` without an allocation or a
/// recorded release.
pub fn recorded_release(
    records: &impl super::handoff::Records,
    public_key: &[u8],
    filter: &[u8],
) -> quil_types::error::Result<Option<Release>> {
    let address = super::materialize::allocation_address(public_key, filter)?;
    Ok(records
        .handoff_vertex(&address)?
        .map(|blob| crate::prover_registry::rebuild_vertex_tree_from_blob(&blob))
        .and_then(|tree| read_release(&tree)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_order_by_version_then_patch_then_subpatch() {
        let r = |version, patch, subpatch| Release {
            version,
            patch,
            subpatch,
        };
        assert!(r([2, 1, 0], 25, 92) > r([2, 1, 0], 25, 91));
        assert!(r([2, 1, 0], 26, 0) > r([2, 1, 0], 25, 900));
        assert!(r([2, 2, 0], 0, 0) > r([2, 1, 9], 255, u16::MAX));
        assert_eq!(r([2, 1, 0], 25, 92).to_string(), "2.1.0.25.92");
        assert_eq!("2.1.0.25.92".parse::<Release>(), Ok(r([2, 1, 0], 25, 92)));
        assert_eq!(
            Release::current().to_string().parse::<Release>(),
            Ok(Release::current())
        );
        for invalid in [
            "2.1.0.25",
            "2.1.0.25.92.1",
            "2.1.0.256.0",
            "2.1.0.25.65536",
            "2.1.x.25.0",
            "",
        ] {
            assert!(invalid.parse::<Release>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn a_release_round_trips_through_its_six_bytes() {
        let release = Release {
            version: [2, 1, 0],
            patch: 25,
            subpatch: 0x0102,
        };
        assert_eq!(release.to_bytes(), [2, 1, 0, 25, 1, 2]);
        assert_eq!(Release::from_bytes(&release.to_bytes()), Some(release));
        assert_eq!(Release::from_bytes(&[2, 1, 0, 25, 1]), None);
        assert_eq!(Release::from_bytes(&[2, 1, 0, 25, 1, 2, 3]), None);
    }

    #[test]
    fn release_frames_and_steps_are_never_set_by_default() {
        // Without `init_*` the getters ignore the environment. Nextest runs
        // each test in its own process, and nothing in this crate's tests
        // calls `init_*`.
        std::env::set_var(CONFIRM_RELEASE_ENV, "0");
        std::env::set_var(RELEASE_ELIGIBILITY_ENV, "0=2.1.0.25.0");
        set_confirm_release_frame_for_thread(None);
        set_release_eligibility_for_thread(None).unwrap();
        assert_eq!(MAINNET_CONFIRM_RELEASE_FRAME, None);
        assert!(MAINNET_RELEASE_ELIGIBILITY.is_empty());
        assert_eq!(confirm_release_frame(), u64::MAX);
        assert_eq!(release_for_confirm(u64::MAX - 1), None);
        assert_eq!(
            minimum_release_at(u64::MAX),
            None,
            "an empty schedule gates nothing"
        );
        assert!(seat_eligible(None, u64::MAX));
        assert_eq!(frame_for(MAINNET_CONFIRM_RELEASE_FRAME, 0, None), u64::MAX);
        assert_eq!(
            frame_for(MAINNET_CONFIRM_RELEASE_FRAME, 0, Some("7")),
            u64::MAX
        );
        assert_eq!(frame_for(MAINNET_CONFIRM_RELEASE_FRAME, 1, Some("7")), 7);
        assert_eq!(
            frame_for(MAINNET_CONFIRM_RELEASE_FRAME, 1, Some("soon")),
            u64::MAX
        );
        assert_eq!(frame_for(MAINNET_CONFIRM_RELEASE_FRAME, 1, None), u64::MAX);
        assert_eq!(schedule_for(0, None), Ok(Vec::new()));
        assert_eq!(
            schedule_for(0, Some("7=2.1.0.25.92")),
            Ok(Vec::new()),
            "mainnet ignores the setting"
        );
        assert_eq!(schedule_for(1, None), Ok(Vec::new()));
        let release: Release = "2.1.0.25.92".parse().unwrap();
        assert_eq!(
            schedule_for(1, Some("7=2.1.0.25.92")),
            Ok(vec![ReleaseMinimum {
                from_frame: 7,
                minimum: release
            }])
        );
        assert!(schedule_for(1, Some("soon=2.1.0.25.92")).is_err());
    }

    #[test]
    fn a_schedule_must_name_strictly_ascending_frames() {
        let release = Release {
            version: [2, 1, 0],
            patch: 25,
            subpatch: 92,
        };
        let step = |from_frame| ReleaseMinimum {
            from_frame,
            minimum: release,
        };
        assert!(validate_schedule(&[]).is_ok());
        assert!(validate_schedule(&[step(5), step(9)]).is_ok());
        assert!(
            validate_schedule(&[step(9), step(5)]).is_err(),
            "descending"
        );
        assert!(validate_schedule(&[step(5), step(5)]).is_err(), "repeated");
        assert!(validate_schedule(MAINNET_RELEASE_ELIGIBILITY).is_ok());
        assert_eq!(parse_schedule(""), Ok(Vec::new()));
        assert_eq!(
            parse_schedule(" 5=2.1.0.25.92, 9=2.1.0.25.92 "),
            Ok(vec![step(5), step(9)])
        );
        assert!(parse_schedule("9=2.1.0.25.92,5=2.1.0.25.92").is_err());
        assert!(parse_schedule("5:2.1.0.25.92").is_err());
        assert!(parse_schedule("5=2.1.0.25").is_err());
        assert!(set_release_eligibility_for_thread(Some(vec![step(9), step(5)])).is_err());
        assert_eq!(
            minimum_release_at(u64::MAX),
            None,
            "a rejected schedule is not installed"
        );
    }

    #[test]
    fn a_confirm_carries_and_binds_its_release_only_from_the_release_frame() {
        let release = Release::current();
        set_confirm_release_frame_for_thread(Some(100));
        assert_eq!(release_for_confirm(99), None);
        assert_eq!(release_for_confirm(100), Some(release));
        assert_eq!(signed_release(99, Some(&release)), None);
        assert_eq!(signed_release(100, Some(&release)), Some(&release));
        assert_eq!(signed_release(100, None), None);
        let early = ProverConfirm {
            frame_number: 99,
            release: Some(release),
            ..Default::default()
        };
        assert_eq!(confirmed_release(&early), None);
        let due = ProverConfirm {
            frame_number: 100,
            ..early
        };
        assert_eq!(confirmed_release(&due), Some(release));
        set_confirm_release_frame_for_thread(None);
    }

    #[test]
    fn a_step_applies_from_its_frame_and_a_later_step_raises_the_minimum_from_its_own() {
        let r = |subpatch| Release {
            version: [2, 1, 0],
            patch: 25,
            subpatch,
        };
        let (old, first, raised) = (r(80), r(90), r(95));
        set_release_eligibility_for_thread(Some(vec![
            ReleaseMinimum {
                from_frame: 100,
                minimum: first,
            },
            ReleaseMinimum {
                from_frame: 200,
                minimum: raised,
            },
        ]))
        .unwrap();
        assert_eq!(minimum_release_at(99), None);
        assert_eq!(minimum_release_at(100), Some(first));
        assert_eq!(minimum_release_at(199), Some(first));
        assert_eq!(minimum_release_at(200), Some(raised));
        assert_eq!(minimum_release_at(u64::MAX), Some(raised));
        for recorded in [None, Some(&old), Some(&first)] {
            assert!(seat_eligible(recorded, 99), "no step before its frame");
        }
        assert!(!seat_eligible(None, 100), "an absent release fails closed");
        assert!(!seat_eligible(Some(&old), 100));
        assert!(seat_eligible(Some(&first), 199));
        assert!(
            !seat_eligible(Some(&first), 200),
            "raised from the later step's frame"
        );
        assert!(seat_eligible(Some(&raised), 200));
        set_release_eligibility_for_thread(None).unwrap();
        assert!(seat_eligible(None, 200));
    }

    #[test]
    fn a_release_is_recorded_on_and_read_from_an_allocation() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        assert_eq!(read_release(&tree), None);
        let release = Release {
            version: [2, 1, 0],
            patch: 25,
            subpatch: 92,
        };
        write_release(&mut tree, &release).unwrap();
        assert_eq!(read_release(&tree), Some(release));
        assert_eq!(
            read_field(&tree, ALLOCATION, "Release").unwrap(),
            vec![2, 1, 0, 25, 0, 92]
        );
    }
}
