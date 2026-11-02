//! Bounded retry of transient RPC failures once a proof is finished.
//!
//! A proof can take many minutes, and the calls that follow it (a fee quote,
//! a connection, the send itself) fail for reasons that pass within seconds
//! or minutes. Throwing the finished proof away for one of them is the worst
//! trade, so the transient classes are retried with jittered exponential
//! backoff for a bounded total, telling the user once. Every other failure
//! is returned at once, as before.
//!
//! Resending the same signed message is safe: the node authenticates it and
//! gossips it, the gossip layer keys messages by the hash of their bytes (a
//! duplicate publishes as success), the proposers' message collectors skip a
//! hash already seen or already included in a finalized frame, and an
//! operation that spends a coin cannot be included twice. A caller must
//! therefore resend the identical bytes and never rebuild the message
//! (a new timestamp is a new message).

use quil_types::proto::node::{node_service_client::NodeServiceClient, SendRequest};
use std::future::Future;
use std::time::Duration;

/// Wait schedule of a retry: the first wait, the cap on one wait (both before
/// jitter) and the total time spent waiting.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub first: Duration,
    pub max: Duration,
    pub budget: Duration,
}

/// A fee quote refused as busy. A quote is a short computation and the node
/// frees a worker as soon as one finishes; a minute outlasts a burst of a
/// dozen quotes against two workers by a wide margin.
pub const QUOTE: Policy = Policy {
    first: Duration::from_secs(1),
    max: Duration::from_secs(8),
    budget: Duration::from_secs(60),
};

/// A connection or a send that did not get through: long enough to outlast a
/// node restart or a network blip, short enough to fail while the user still
/// has the terminal.
pub const DELIVERY: Policy = Policy {
    first: Duration::from_secs(2),
    max: Duration::from_secs(30),
    budget: Duration::from_secs(300),
};

#[cfg(test)]
pub(crate) static NO_WAIT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Sleep, except in tests that switched waiting off.
async fn pause(delay: Duration) {
    #[cfg(test)]
    {
        if NO_WAIT.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
    }
    tokio::time::sleep(delay).await;
}

/// The wait before retry number `retry` (0 for the first), scaled by `unit`
/// in `[0, 1]`: "equal jitter", between half and all of the exponential step,
/// so clients refused together do not return together.
pub fn backoff_delay(policy: &Policy, retry: u32, unit: f64) -> Duration {
    let step = policy
        .first
        .saturating_mul(1u32.checked_shl(retry).unwrap_or(u32::MAX))
        .min(policy.max);
    step.mul_f64(0.5 + 0.5 * unit.clamp(0.0, 1.0))
}

/// Call `call` until it succeeds, fails with an error `retryable` rejects, or
/// `policy.budget` of waiting would be exceeded, and return the last result.
/// `wait` sleeps (injected so tests need no real time), `unit` draws jitter in
/// `[0, 1]` and `notice` runs once, before the first wait.
pub async fn retry_while<T, E, C, CF, W, WF>(
    policy: Policy,
    retryable: impl Fn(&E) -> bool,
    mut unit: impl FnMut() -> f64,
    mut notice: impl FnMut(&E, Duration),
    mut wait: W,
    mut call: C,
) -> Result<T, E>
where
    C: FnMut() -> CF,
    CF: Future<Output = Result<T, E>>,
    W: FnMut(Duration) -> WF,
    WF: Future<Output = ()>,
{
    let mut waited = Duration::ZERO;
    let mut retry = 0u32;
    loop {
        match call().await {
            Err(error) if retryable(&error) => {
                let delay = backoff_delay(&policy, retry, unit());
                if waited + delay > policy.budget {
                    return Err(error);
                }
                if retry == 0 {
                    notice(&error, policy.budget);
                }
                wait(delay).await;
                waited += delay;
                retry += 1;
            }
            other => return other,
        }
    }
}

/// The node's fee quote workers are all taken.
pub fn busy(status: &tonic::Status) -> bool {
    status.code() == tonic::Code::ResourceExhausted
}

/// A status that says the call may not have reached the node's logic, or that
/// the node could not serve it now, rather than that the node refused it:
/// worth another try, and not a verdict on the request. The node answers a
/// refusal of the request itself with InvalidArgument, FailedPrecondition,
/// Internal or Unauthenticated (its send handler reports every rejection as
/// the last), none of which is listed.
pub fn transient(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::Unavailable
            | tonic::Code::DeadlineExceeded
            | tonic::Code::Aborted
            | tonic::Code::Cancelled
            | tonic::Code::Unknown
            | tonic::Code::ResourceExhausted
    )
}

/// A quote status after which a finished proof is still submitted with the
/// supplied fee for the node to validate: the node cannot quote now, or never
/// could (an old node).
pub fn cannot_quote(code: tonic::Code) -> bool {
    transient(code) || code == tonic::Code::Unimplemented
}

/// Quote `request` from `client`, retrying a busy refusal for up to
/// [`QUOTE`]'s budget and telling the user once when it does.
#[cfg(feature = "native-proof")]
pub async fn quote(
    client: &NodeServiceClient<tonic::transport::Channel>,
    request: quil_types::proto::node::GetTokenFeeQuoteRequest,
) -> Result<tonic::Response<quil_types::proto::node::GetTokenFeeQuoteResponse>, tonic::Status> {
    retry_while(
        QUOTE,
        busy,
        rand::random::<f64>,
        |_, budget| {
            crate::commands::token::output::line(format!(
                "The node's fee quote workers are busy; retrying for up to {} s.",
                budget.as_secs()
            ))
        },
        pause,
        || {
            let mut client = client.clone();
            let request = request.clone();
            async move { client.get_token_fee_quote(request).await }
        },
    )
    .await
}

/// Send an already-signed request, resending the identical request when the
/// node could not be reached or did not answer in time (see the module notes
/// for why a duplicate is harmless, even when only the reply was lost).
/// A refusal by the node is returned at once.
pub async fn deliver(
    client: &NodeServiceClient<tonic::transport::Channel>,
    request: SendRequest,
) -> Result<(), tonic::Status> {
    retry_while(
        DELIVERY,
        |status: &tonic::Status| transient(status.code()),
        rand::random::<f64>,
        |status, budget| {
            crate::commands::token::output::line(format!(
                "The node did not take the submission ({}); resending it for up to {} s.",
                status.code(),
                budget.as_secs()
            ))
        },
        pause,
        || {
            let mut client = client.clone();
            let request = request.clone();
            async move { client.send(tonic::Request::new(request)).await.map(|_| ()) }
        },
    )
    .await
}

/// Connect with `connect`, retrying any failure for up to [`DELIVERY`]'s
/// budget: nothing was sent over a connection that failed, so retrying is
/// safe, and after a long proof an unreachable node is far more likely a
/// restart than a wrong address (which the command's earlier calls would
/// already have hit).
pub async fn connect<T, F, Fut>(mut connect: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    retry_while(
        DELIVERY,
        |_| true,
        rand::random::<f64>,
        |error: &anyhow::Error, budget| {
            crate::commands::token::output::line(format!(
                "Cannot reach the node ({error:#}); retrying for up to {} s.",
                budget.as_secs()
            ))
        },
        pause,
        &mut connect,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn busy_status() -> tonic::Status {
        tonic::Status::resource_exhausted("fee quote workers busy")
    }

    /// Drive `retry_while` over the busy class with a scripted node and a
    /// virtual clock. Returns the result, the calls made, the waits and the
    /// notices.
    async fn drive(
        script: Vec<Result<u8, tonic::Status>>,
        unit: f64,
    ) -> (Result<u8, tonic::Status>, usize, Vec<Duration>, usize) {
        let script = RefCell::new(script.into_iter());
        let calls = Cell::new(0usize);
        let waits = RefCell::new(Vec::new());
        let notices = Cell::new(0usize);
        let result = retry_while(
            QUOTE,
            busy,
            || unit,
            |_, _| notices.set(notices.get() + 1),
            |delay| {
                waits.borrow_mut().push(delay);
                async {}
            },
            || {
                calls.set(calls.get() + 1);
                let next = script
                    .borrow_mut()
                    .next()
                    .unwrap_or_else(|| Err(busy_status()));
                async move { next }
            },
        )
        .await;
        (result, calls.get(), waits.into_inner(), notices.get())
    }

    #[tokio::test]
    async fn a_busy_refusal_is_retried_until_a_worker_is_free() {
        let (result, calls, waits, notices) =
            drive(vec![Err(busy_status()), Err(busy_status()), Ok(7)], 1.0).await;
        assert_eq!(
            result.unwrap(),
            7,
            "the quote must succeed once a worker frees"
        );
        assert_eq!(calls, 3);
        assert_eq!(waits, [Duration::from_secs(1), Duration::from_secs(2)]);
        assert_eq!(notices, 1, "the user is told once, not per retry");
    }

    #[tokio::test]
    async fn a_node_that_stays_busy_is_given_up_on_within_the_budget() {
        let (result, calls, waits, notices) = drive(vec![], 1.0).await;
        assert_eq!(result.unwrap_err().code(), tonic::Code::ResourceExhausted);
        assert!(calls > 2 && calls < 30, "bounded attempts, got {calls}");
        assert_eq!(calls, waits.len() + 1);
        assert!(waits.iter().sum::<Duration>() <= QUOTE.budget);
        assert!(
            waits.iter().all(|delay| *delay <= QUOTE.max),
            "no single wait is past the cap: {waits:?}"
        );
        assert_eq!(notices, 1);
    }

    #[tokio::test]
    async fn every_other_status_fails_at_once_without_a_wait() {
        for status in [
            tonic::Status::unavailable("down"),
            tonic::Status::unimplemented("old node"),
            tonic::Status::internal("boom"),
            tonic::Status::deadline_exceeded("slow"),
            tonic::Status::invalid_argument("bad"),
        ] {
            let code = status.code();
            let (result, calls, waits, notices) = drive(vec![Err(status), Ok(1)], 0.0).await;
            assert_eq!(result.unwrap_err().code(), code);
            assert_eq!(
                (calls, waits.len(), notices),
                (1, 0, 0),
                "{code:?} was retried"
            );
        }
    }

    #[tokio::test]
    async fn a_first_success_makes_one_call_and_no_notice() {
        let (result, calls, waits, notices) = drive(vec![Ok(3)], 0.5).await;
        assert_eq!(result.unwrap(), 3);
        assert_eq!((calls, waits.len(), notices), (1, 0, 0));
    }

    #[test]
    fn backoff_doubles_to_a_cap_and_jitters_between_half_and_all() {
        let full: Vec<u64> = (0..6)
            .map(|n| backoff_delay(&QUOTE, n, 1.0).as_millis() as u64)
            .collect();
        assert_eq!(full, [1000, 2000, 4000, 8000, 8000, 8000]);
        assert_eq!(backoff_delay(&QUOTE, 2, 0.0), Duration::from_secs(2));
        assert_eq!(backoff_delay(&QUOTE, 2, 0.5), Duration::from_secs(3));
        assert_eq!(backoff_delay(&QUOTE, u32::MAX, 1.0), QUOTE.max);
        assert_eq!(
            backoff_delay(&QUOTE, 0, 7.0),
            Duration::from_secs(1),
            "jitter is clamped"
        );
        assert_eq!(backoff_delay(&DELIVERY, 9, 1.0), DELIVERY.max);
    }

    #[test]
    fn only_transient_statuses_are_retried_or_kept() {
        use tonic::Code::*;
        for code in [
            Unavailable,
            DeadlineExceeded,
            Aborted,
            Cancelled,
            Unknown,
            ResourceExhausted,
        ] {
            assert!(transient(code), "{code:?} is transient");
            assert!(cannot_quote(code), "{code:?} keeps a finished proof");
        }
        // Unimplemented is an old node: no quote, but not worth resending.
        assert!(!transient(Unimplemented) && cannot_quote(Unimplemented));
        // The node's own refusals stay failures.
        for code in [
            InvalidArgument,
            FailedPrecondition,
            Internal,
            Unauthenticated,
            PermissionDenied,
            NotFound,
            AlreadyExists,
            OutOfRange,
            DataLoss,
        ] {
            assert!(
                !transient(code) && !cannot_quote(code),
                "{code:?} is a refusal"
            );
        }
    }

    #[tokio::test]
    async fn connect_errors_are_retried_until_the_budget() {
        NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
        let calls = Cell::new(0usize);
        let connected = connect(|| {
            calls.set(calls.get() + 1);
            let attempt = calls.get();
            async move {
                if attempt < 4 {
                    Err(anyhow::anyhow!("connection refused"))
                } else {
                    Ok(attempt)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!((connected, calls.get()), (4, 4));
        calls.set(0);
        let error = connect(|| {
            calls.set(calls.get() + 1);
            async { Err::<u8, _>(anyhow::anyhow!("connection refused")) }
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("connection refused"));
        assert!(
            calls.get() > 4 && calls.get() < 40,
            "bounded attempts, got {}",
            calls.get()
        );
    }
}
