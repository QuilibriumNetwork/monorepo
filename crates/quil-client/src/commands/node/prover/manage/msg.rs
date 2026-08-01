//! Async messages delivered into the TUI event loop (the bubbletea
//! `tea.Msg` equivalents produced by the async action commands).

use quil_types::proto::node::{GetShardInfoResponse, NodeInfoResponse, WorkerInfoResponse};

use super::model::FilterOutcome;

pub enum Msg {
    /// `dataRefreshMsg` — result of a full RPC data fetch.
    DataRefresh {
        node_info: Option<NodeInfoResponse>,
        shard_info: Option<GetShardInfoResponse>,
        worker_info: Option<WorkerInfoResponse>,
        err: Option<String>,
    },
    /// `actionResultMsg` — RequestJoin RPC ack (Join only).
    ActionResult {
        action: String,
        filter: String,
        filters_raw: Vec<Vec<u8>>,
        err: Option<String>,
    },
    /// `actionBroadcastMsg` — a signed lifecycle op was broadcast.
    ActionBroadcast {
        action: String,
        filters_raw: Vec<Vec<u8>>,
        send_frame: u64,
        original_status: u32,
        err: Option<String>,
    },
    /// `toggleManualMsg` — SetManuallyManaged result for one worker.
    ToggleManual {
        core_id: u32,
        new_state: bool,
        err: Option<String>,
    },
    /// `markManualMsg` — batch SetManuallyManaged result.
    MarkManual {
        worker_ids: Vec<u32>,
        failed_ids: Vec<u32>,
        err: Option<String>,
    },
    /// `awaitCheckMsg` — timer fired; poll allocation status.
    AwaitCheck,
    /// `awaitResultMsg` — result of one allocation-status poll.
    AwaitResult {
        action: String,
        frame: u64,
        err: Option<String>,
        per_filter: Vec<FilterOutcome>,
    },
}
