use crate::error::Result;
use tokio_util::sync::CancellationToken;

/// Error handling behavior when a component fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorHandlingBehavior {
    /// Restart the failed component.
    ShouldRestart,
    /// Stop only this component.
    ShouldStop,
    /// Stop this component and its parents.
    ShouldStopParents,
    /// Shut down the entire application.
    ShouldShutdown,
    /// Spin-halt (busy wait for external intervention).
    ShouldSpinHalt,
}

/// A managed component with lifecycle hooks.
#[async_trait::async_trait]
pub trait Component: Send + Sync {
    /// Start the component. Blocks until the component is done or cancelled.
    async fn start(&self, token: CancellationToken) -> Result<()>;

    /// Returns a receiver that signals when the component is ready.
    fn ready(&self) -> tokio::sync::watch::Receiver<bool>;
}
