//! View settings kept between runs, per user, in one small file beside the
//! qclient config (`~/.quilibrium/qclient-node-manage.yaml`): visible
//! columns and their order, hidden KPIs and their fields, panel edges,
//! sort, colors, thresholds mode, notice level, refresh interval and the
//! key rows. Filter text, scroll, selection and expanded rows are not
//! kept. Each entry is read on its own: an unknown, renamed or malformed
//! entry is skipped and the rest still apply, so a newer or older qclient
//! never fails on the file.

use std::path::{Path, PathBuf};

use serde_yaml::{Mapping, Value};

use super::super::epoch::ThresholdUnit;
use super::model::{
    Model, NoticeSeverity, ALLOC_COL_NAMES, ALLOC_DISPLAY_COLS, ALLOC_KPI_NAMES, AVAIL_COL_NAMES,
    AVAIL_DISPLAY_COLS, AVAIL_KPI_NAMES, NOTICE_KPI_NAMES, TOP_KPI_NAMES,
};

/// The file's name in the qclient config directory.
pub const FILE_NAME: &str = "qclient-node-manage.yaml";

/// Refresh intervals `t` cycles through.
const REFRESH_SECONDS: [u64; 4] = [5, 15, 30, 60];

/// Where this user's view settings live; `None` without a home directory.
pub fn default_path() -> Option<PathBuf> {
    crate::config::config_dir()
        .ok()
        .map(|dir| dir.join(FILE_NAME))
}

fn names(indices: impl IntoIterator<Item = usize>, table: &[&str]) -> Value {
    Value::Sequence(
        indices
            .into_iter()
            .filter_map(|i| table.get(i))
            .map(|name| Value::String((*name).to_string()))
            .collect(),
    )
}

fn severity_name(severity: NoticeSeverity) -> &'static str {
    match severity {
        NoticeSeverity::Info => "info",
        NoticeSeverity::Warning => "warning",
        NoticeSeverity::Error => "error",
    }
}

fn sort_name(col: i32, table: &[&str]) -> Value {
    usize::try_from(col)
        .ok()
        .and_then(|col| table.get(col))
        .map_or(Value::String(String::new()), |name| {
            Value::String((*name).to_string())
        })
}

/// The model's kept settings, as the file stores them.
pub fn capture(m: &Model) -> Mapping {
    let mut hidden: Vec<usize> = m.hidden_columns.iter().copied().collect();
    hidden.sort_unstable();
    let mut kpis: Vec<&String> = m.hidden_header_kpis.iter().collect();
    kpis.sort();
    let mut out = Mapping::new();
    let mut put = |key: &str, value: Value| {
        out.insert(Value::String(key.into()), value);
    };
    put("version", 1.into());
    put("hiddenColumns", names(hidden, &ALLOC_COL_NAMES));
    put(
        "allocationColumns",
        names(m.alloc_column_order.iter().copied(), &ALLOC_COL_NAMES),
    );
    put(
        "availableColumns",
        names(m.avail_column_order.iter().copied(), &AVAIL_COL_NAMES),
    );
    put(
        "hiddenKpis",
        Value::Sequence(kpis.into_iter().map(|k| Value::String(k.clone())).collect()),
    );
    put("rewardWindows", m.reward_windows.into());
    put("intervalWindows", m.interval_windows.into());
    put("globalIntervalWindows", m.global_interval_windows.into());
    put("globalFields", m.global_fields.into());
    put(
        "panelEdges",
        Value::Sequence(
            m.panel_boundary_offsets
                .iter()
                .map(|&edge| Value::from(i64::from(edge)))
                .collect(),
        ),
    );
    put(
        "coinsPanelEdges",
        Value::Sequence(
            m.coins
                .edges
                .iter()
                .map(|&edge| Value::from(i64::from(edge)))
                .collect(),
        ),
    );
    put(
        "allocationSortColumn",
        sort_name(m.alloc_sort_col, &ALLOC_COL_NAMES),
    );
    put("allocationSortAscending", m.alloc_sort_asc.into());
    put(
        "availableSortColumn",
        sort_name(m.avail_sort_col, &AVAIL_COL_NAMES),
    );
    put("availableSortAscending", m.avail_sort_asc.into());
    put("colors", m.color_coding.into());
    put("thresholds", m.threshold_unit.label().into());
    put("noticeLevel", severity_name(m.notice_minimum).into());
    put("refreshSeconds", m.refresh_seconds.into());
    put("keyRows", m.show_key_rows.into());
    out
}

fn get<'a>(map: &'a Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.into()))
}

fn index_of(name: &Value, table: &[&str]) -> Option<usize> {
    let name = name.as_str()?;
    table.iter().position(|known| *known == name)
}

/// A saved column order, kept only while it names exactly the columns
/// this build shows: a renamed, added or removed column voids it.
fn column_order(value: &Value, table: &[&str], default: &[usize]) -> Option<Vec<usize>> {
    let order: Vec<usize> = value
        .as_sequence()?
        .iter()
        .map(|name| index_of(name, table))
        .collect::<Option<_>>()?;
    let mut sorted = order.clone();
    sorted.sort_unstable();
    let mut expected = default.to_vec();
    expected.sort_unstable();
    (sorted == expected).then_some(order)
}

fn mask(value: &Value, max: u8) -> Option<u8> {
    let mask = u8::try_from(value.as_u64()?).ok()?;
    (1..=max).contains(&mask).then_some(mask)
}

fn sort_column(value: &Value, table: &[&str]) -> Option<i32> {
    match value.as_str()? {
        "" => Some(-1),
        // Select and Filter never sort.
        _ => index_of(value, table)
            .filter(|&col| col >= 2)
            .map(|col| col as i32),
    }
}

/// Apply every valid entry of `map` to the model; others are skipped.
pub fn apply(m: &mut Model, map: &Mapping) {
    if let Some(list) = get(map, "hiddenColumns").and_then(Value::as_sequence) {
        // Select and Filter cannot be hidden.
        m.hidden_columns = list
            .iter()
            .filter_map(|name| index_of(name, &ALLOC_COL_NAMES))
            .filter(|&col| col >= 2)
            .collect();
    }
    if let Some(order) = get(map, "allocationColumns")
        .and_then(|v| column_order(v, &ALLOC_COL_NAMES, ALLOC_DISPLAY_COLS))
    {
        m.alloc_column_order = order;
    }
    if let Some(order) = get(map, "availableColumns")
        .and_then(|v| column_order(v, &AVAIL_COL_NAMES, AVAIL_DISPLAY_COLS))
    {
        m.avail_column_order = order;
    }
    if let Some(list) = get(map, "hiddenKpis").and_then(Value::as_sequence) {
        let known = |name: &str| {
            [
                TOP_KPI_NAMES,
                ALLOC_KPI_NAMES,
                AVAIL_KPI_NAMES,
                NOTICE_KPI_NAMES,
            ]
            .iter()
            .any(|names| names.contains(&name))
        };
        m.hidden_header_kpis = list
            .iter()
            .filter_map(Value::as_str)
            .filter(|name| known(name))
            .map(str::to_string)
            .collect();
    }
    if let Some(v) = get(map, "rewardWindows").and_then(|v| mask(v, 7)) {
        m.reward_windows = v;
    }
    if let Some(v) = get(map, "intervalWindows").and_then(|v| mask(v, 3)) {
        m.interval_windows = v;
    }
    if let Some(v) = get(map, "globalIntervalWindows").and_then(|v| mask(v, 3)) {
        m.global_interval_windows = v;
    }
    if let Some(v) = get(map, "globalFields").and_then(|v| mask(v, 7)) {
        m.global_fields = v;
    }
    if let Some([upper, lower]) = get(map, "panelEdges")
        .and_then(Value::as_sequence)
        .and_then(|edges| {
            edges
                .iter()
                .map(|edge| edge.as_i64().and_then(|e| i16::try_from(e).ok()))
                .collect::<Option<Vec<i16>>>()
        })
        .and_then(|edges| <[i16; 2]>::try_from(edges).ok())
    {
        // Drawing clamps edges to the terminal; this bounds absurd values.
        m.panel_boundary_offsets = [upper.clamp(-500, 500), lower.clamp(-500, 500)];
    }
    // The Coins tab's own edges, apart from the Provers tab's. A list with
    // more or fewer edges (another qclient's tab) sets those it shares.
    if let Some(edges) = get(map, "coinsPanelEdges")
        .and_then(Value::as_sequence)
        .and_then(|edges| {
            edges
                .iter()
                .map(|edge| edge.as_i64().and_then(|e| i16::try_from(e).ok()))
                .collect::<Option<Vec<i16>>>()
        })
    {
        m.coins.edges = Default::default();
        for (kept, edge) in m.coins.edges.iter_mut().zip(edges) {
            *kept = edge.clamp(-500, 500);
        }
    }
    if let Some(col) =
        get(map, "allocationSortColumn").and_then(|v| sort_column(v, &ALLOC_COL_NAMES))
    {
        m.alloc_sort_col = col;
    }
    if let Some(asc) = get(map, "allocationSortAscending").and_then(Value::as_bool) {
        m.alloc_sort_asc = asc;
    }
    if let Some(col) =
        get(map, "availableSortColumn").and_then(|v| sort_column(v, &AVAIL_COL_NAMES))
    {
        m.avail_sort_col = col;
    }
    if let Some(asc) = get(map, "availableSortAscending").and_then(Value::as_bool) {
        m.avail_sort_asc = asc;
    }
    if let Some(colors) = get(map, "colors").and_then(Value::as_bool) {
        m.color_coding = colors;
    }
    match get(map, "thresholds").and_then(Value::as_str) {
        Some("relative") => m.threshold_unit = ThresholdUnit::Relative,
        Some("absolute") => m.threshold_unit = ThresholdUnit::Absolute,
        _ => {}
    }
    match get(map, "noticeLevel").and_then(Value::as_str) {
        Some("info") => m.notice_minimum = NoticeSeverity::Info,
        Some("warning") => m.notice_minimum = NoticeSeverity::Warning,
        Some("error") => m.notice_minimum = NoticeSeverity::Error,
        _ => {}
    }
    if let Some(seconds) = get(map, "refreshSeconds")
        .and_then(Value::as_u64)
        .filter(|s| REFRESH_SECONDS.contains(s))
    {
        m.refresh_seconds = seconds;
    }
    if let Some(shown) = get(map, "keyRows").and_then(Value::as_bool) {
        m.show_key_rows = shown;
    }
}

/// Restore every kept setting to its default; the rest of the view stays.
pub fn restore_defaults(m: &mut Model) {
    apply(m, &capture(&Model::new()));
}

/// The settings of the file at `path`; an empty mapping when it is
/// missing or not a YAML mapping at all.
pub fn read(path: &Path) -> Mapping {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_yaml::from_str::<Value>(&text).ok())
        .and_then(|value| match value {
            Value::Mapping(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default()
}

/// Write `map` to `path` through a temporary file, so a crash never
/// leaves half a file.
fn write(path: &Path, map: &Mapping) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, serde_yaml::to_string(map)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The interactive view's settings file: written whenever a kept setting
/// changes, never by `--render`.
pub struct Store {
    path: Option<PathBuf>,
    saved: Mapping,
    /// The last write failed; reported once until a write succeeds.
    failed: bool,
}

impl Store {
    /// Open the file at `path` and apply it to the model.
    pub fn open(path: Option<PathBuf>, m: &mut Model) -> Self {
        if let Some(path) = &path {
            apply(m, &read(path));
        }
        Self {
            path,
            saved: capture(m),
            failed: false,
        }
    }

    /// Save the model's settings when they changed; returns the error of a
    /// failed write the first time it fails.
    pub fn sync(&mut self, m: &Model) -> Option<String> {
        let current = capture(m);
        if current == self.saved {
            return None;
        }
        let path = self.path.as_ref()?;
        match write(path, &current) {
            Ok(()) => {
                self.saved = current;
                self.failed = false;
                None
            }
            Err(error) if !self.failed => {
                self.failed = true;
                Some(format!("{error:#}"))
            }
            Err(_) => None,
        }
    }
}

/// `--reset-ui`: remove the saved view settings, so the view opens with
/// its defaults. A missing file is already reset.
pub fn reset(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("qclient-node-manage-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join(FILE_NAME)
    }

    /// A model with every kept setting moved off its default.
    fn changed() -> Model {
        let mut m = Model::new();
        m.hidden_columns = [4, 16].into_iter().collect();
        m.alloc_column_order.swap(2, 3);
        m.avail_column_order.swap(2, 3);
        m.hidden_header_kpis.insert("Seniority".into());
        m.reward_windows = 2;
        m.interval_windows = 1;
        m.global_interval_windows = 2;
        m.global_fields = 5;
        m.panel_boundary_offsets = [-2, 3];
        m.coins.edges = [1, -2];
        m.alloc_sort_col = 10;
        m.alloc_sort_asc = false;
        m.avail_sort_col = -1;
        m.avail_sort_asc = true;
        m.color_coding = false;
        m.threshold_unit = ThresholdUnit::Absolute;
        m.notice_minimum = NoticeSeverity::Info;
        m.refresh_seconds = 60;
        m.show_key_rows = false;
        m
    }

    #[test]
    fn every_kept_setting_survives_a_restart() {
        let path = scratch("restart");
        let before = changed();
        let mut store = Store::open(Some(path.clone()), &mut Model::new());
        assert_eq!(store.sync(&before), None);
        let mut after = Model::new();
        Store::open(Some(path.clone()), &mut after);
        assert_eq!(capture(&after), capture(&before));
        assert_ne!(capture(&after), capture(&Model::new()));
        // Not kept: filters, scroll, selection, the tab.
        let mut m = changed();
        m.alloc_selected.insert("x".into());
        m.notice_offset = 4;
        assert_eq!(capture(&m), capture(&before));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn unknown_and_stale_entries_are_skipped() {
        let path = scratch("stale");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "version: 9\nfutureSetting: 3\nhiddenColumns: [\"Size [GB]\", Renamed]\n\
             allocationColumns: [Select, Filter]\nrefreshSeconds: 7\nnoticeLevel: loud\n\
             rewardWindows: 0\nkeyRows: false\ncolors: maybe\npanelEdges: [1]\n\
             availableSortColumn: Gone\nthresholds: absolute\n",
        )
        .unwrap();
        let mut m = Model::new();
        Store::open(Some(path.clone()), &mut m);
        let defaults = Model::new();
        // The valid entries apply...
        assert_eq!(m.hidden_columns, [4].into_iter().collect());
        assert!(!m.show_key_rows);
        assert_eq!(m.threshold_unit, ThresholdUnit::Absolute);
        // ...and the rest keep their defaults.
        assert_eq!(m.alloc_column_order, defaults.alloc_column_order);
        assert_eq!(m.refresh_seconds, defaults.refresh_seconds);
        assert_eq!(m.notice_minimum, defaults.notice_minimum);
        assert_eq!(m.reward_windows, defaults.reward_windows);
        assert_eq!(m.color_coding, defaults.color_coding);
        assert_eq!(m.panel_boundary_offsets, defaults.panel_boundary_offsets);
        assert_eq!(m.avail_sort_col, defaults.avail_sort_col);
        // Not YAML at all: every default.
        std::fs::write(&path, "{{{ not yaml").unwrap();
        let mut m = Model::new();
        Store::open(Some(path.clone()), &mut m);
        assert_eq!(capture(&m), capture(&defaults));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// The Coins tab's edges load by position under their own key: a list
    /// with a value that is no edge is skipped, a shorter or longer one sets
    /// the edges it holds; `--reset-ui` drops them with the file.
    #[test]
    fn coins_edges_load_by_position_and_skip_malformed_lists() {
        let path = scratch("coins-edges");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let open = |text: &str| {
            std::fs::write(&path, text).unwrap();
            let mut m = Model::new();
            m.coins.edges = [5; super::super::coins::EDGES];
            Store::open(Some(path.clone()), &mut m);
            m
        };
        let m = open("coinsPanelEdges: [1, x]\npanelEdges: [2, 3]\n");
        assert_eq!(m.coins.edges, [5, 5]);
        assert_eq!(m.panel_boundary_offsets, [2, 3]);
        assert_eq!(open("coinsPanelEdges: [4]\n").coins.edges, [4, 0]);
        assert_eq!(
            open("coinsPanelEdges: [1, -2, 3, 4]\n").coins.edges,
            [1, -2]
        );
        assert_eq!(
            open("coinsPanelEdges: [9000, -9000]\n").coins.edges,
            [500, -500]
        );
        assert_eq!(open("coinsPanelEdges: 3\n").coins.edges, [5, 5]);
        // The Provers tab's edges stay its own.
        let m = open("coinsPanelEdges: [4, 4]\n");
        assert_eq!(
            m.panel_boundary_offsets,
            Model::new().panel_boundary_offsets
        );
        reset(&path).unwrap();
        let mut m = Model::new();
        Store::open(Some(path.clone()), &mut m);
        assert_eq!(m.coins.edges, [0, 0]);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn writes_only_on_change_and_reset_restores_defaults() {
        let path = scratch("reset");
        let mut m = Model::new();
        let mut store = Store::open(Some(path.clone()), &mut m);
        assert_eq!(store.sync(&m), None);
        assert!(!path.exists(), "unchanged defaults need no file");
        m.refresh_seconds = 30;
        assert_eq!(store.sync(&m), None);
        assert!(path.exists());
        reset(&path).unwrap();
        reset(&path).unwrap();
        let mut reopened = Model::new();
        Store::open(Some(path.clone()), &mut reopened);
        assert_eq!(reopened.refresh_seconds, 15);
        let mut m = changed();
        restore_defaults(&mut m);
        assert_eq!(capture(&m), capture(&Model::new()));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
