//! The core each local data worker thread is pinned to.
//!
//! A worker's memory is placed on the NUMA node of the core that first
//! touches it, so pinning places the memory too. Taken in CPU order, the
//! cores fill the first nodes before the others get a worker: those nodes
//! run short of memory and swap while the others' stays idle. The layout
//! takes the nodes in turn instead, keeping the workers, and their memory,
//! balanced across them.

use std::collections::BTreeMap;
use std::path::Path;

use core_affinity::CoreId;

/// Where the kernel lists each NUMA node's CPUs, as `node<N>/cpulist`.
const NODE_ROOT: &str = "/sys/devices/system/node";

/// The cores worker threads are pinned to: worker `k` takes `cores[k]`, and
/// index 0 is left to the master. Workers past the end run unpinned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PinLayout {
    /// Each core with its NUMA node; no node where the topology is unknown.
    cores: Vec<(usize, Option<u32>)>,
}

impl PinLayout {
    /// The layout for the CPUs the calling thread may run on: at startup,
    /// the process's affinity mask, which a cgroup cpuset also narrows.
    pub(crate) fn detect() -> Self {
        let allowed: Vec<usize> = core_affinity::get_core_ids()
            .unwrap_or_default()
            .into_iter()
            .map(|core| core.id)
            .collect();
        Self::new(read_nodes(Path::new(NODE_ROOT)).as_deref(), &allowed)
    }

    /// Order `allowed` (ascending, as the affinity mask lists it) round-robin
    /// over the NUMA nodes holding any of them, each node's CPUs ascending.
    /// One such node, no topology, or an allowed CPU it does not place keep
    /// the plain order.
    pub(crate) fn new(nodes: Option<&[(u32, Vec<usize>)]>, allowed: &[usize]) -> Self {
        let node_of = |cpu: usize| {
            nodes?
                .iter()
                .find(|(_, cpus)| cpus.contains(&cpu))
                .map(|&(node, _)| node)
        };
        let mut by_node: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for &cpu in allowed {
            let Some(node) = node_of(cpu) else {
                return Self {
                    cores: allowed.iter().map(|&cpu| (cpu, None)).collect(),
                };
            };
            by_node.entry(node).or_default().push(cpu);
        }
        if by_node.len() < 2 {
            let node = by_node.keys().next().copied();
            return Self {
                cores: allowed.iter().map(|&cpu| (cpu, node)).collect(),
            };
        }
        let mut queues: Vec<(u32, std::vec::IntoIter<usize>)> = by_node
            .into_iter()
            .map(|(node, cpus)| (node, cpus.into_iter()))
            .collect();
        let mut cores = Vec::with_capacity(allowed.len());
        while cores.len() < allowed.len() {
            for (node, queue) in &mut queues {
                if let Some(cpu) = queue.next() {
                    cores.push((cpu, Some(*node)));
                }
            }
        }
        Self { cores }
    }

    /// The core worker `worker` is pinned to, if any.
    pub(crate) fn core(&self, worker: u32) -> Option<CoreId> {
        self.cores
            .get(worker as usize)
            .map(|&(id, _)| CoreId { id })
    }

    /// The NUMA node of the core worker `worker` is pinned to, if known.
    pub(crate) fn node(&self, worker: u32) -> Option<u32> {
        self.cores.get(worker as usize)?.1
    }

    /// CPUs the layout holds, the master's slot included.
    pub(crate) fn len(&self) -> usize {
        self.cores.len()
    }

    /// Workers `1..=workers` left without a core.
    pub(crate) fn unpinned(&self, workers: u32) -> usize {
        (workers as usize).saturating_sub(self.cores.len().saturating_sub(1))
    }

    /// How the cores are ordered, for the startup line.
    pub(crate) fn order(&self) -> &'static str {
        match self.cores.first() {
            None | Some((_, None)) => "CPU order: NUMA topology unknown",
            _ if self.per_node(0).0.len() > 1 => "round-robin over NUMA nodes",
            _ => "CPU order: one NUMA node",
        }
    }

    /// Cores, and those workers `1..=workers` are pinned to, per NUMA node;
    /// empty where the topology is unknown.
    pub(crate) fn per_node(&self, workers: u32) -> (BTreeMap<u32, usize>, BTreeMap<u32, usize>) {
        let mut cores = BTreeMap::new();
        let mut pinned = BTreeMap::new();
        for (slot, &(_, node)) in self.cores.iter().enumerate() {
            let Some(node) = node else { continue };
            *cores.entry(node).or_insert(0) += 1;
            let entry = pinned.entry(node).or_insert(0);
            if (1..=workers as usize).contains(&slot) {
                *entry += 1;
            }
        }
        (cores, pinned)
    }
}

/// `node=count` pairs, e.g. `0=16 1=16`.
pub(crate) fn node_counts(counts: &BTreeMap<u32, usize>) -> String {
    counts
        .iter()
        .map(|(node, count)| format!("{node}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Each NUMA node's CPUs, by node id; `None` where sysfs lists no node or
/// one cannot be read.
fn read_nodes(root: &Path) -> Option<Vec<(u32, Vec<usize>)>> {
    let mut nodes = Vec::new();
    for entry in std::fs::read_dir(root).ok()?.flatten() {
        let name = entry.file_name();
        let Some(node) = name
            .to_str()
            .and_then(|name| name.strip_prefix("node"))
            .and_then(|id| id.parse().ok())
        else {
            continue;
        };
        let list = std::fs::read_to_string(entry.path().join("cpulist")).ok()?;
        nodes.push((node, parse_cpulist(&list)?));
    }
    nodes.sort_unstable_by_key(|&(node, _)| node);
    (!nodes.is_empty()).then_some(nodes)
}

/// A kernel CPU list such as `0-7,32-39`; empty for a node without CPUs.
fn parse_cpulist(list: &str) -> Option<Vec<usize>> {
    let mut cpus = Vec::new();
    for range in list.trim().split(',').filter(|range| !range.is_empty()) {
        let (first, last): (usize, usize) = match range.split_once('-') {
            Some((first, last)) => (first.parse().ok()?, last.parse().ok()?),
            None => {
                let cpu = range.parse().ok()?;
                (cpu, cpu)
            }
        };
        if first > last {
            return None;
        }
        cpus.extend(first..=last);
    }
    Some(cpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `count` nodes of `per_node` CPUs each, numbered node after node.
    fn contiguous(count: u32, per_node: usize) -> Vec<(u32, Vec<usize>)> {
        (0..count)
            .map(|node| {
                let first = node as usize * per_node;
                (node, (first..first + per_node).collect())
            })
            .collect()
    }

    fn all(nodes: &[(u32, Vec<usize>)]) -> Vec<usize> {
        let mut cpus: Vec<usize> = nodes.iter().flat_map(|(_, cpus)| cpus.clone()).collect();
        cpus.sort_unstable();
        cpus
    }

    fn cpus(layout: &PinLayout) -> Vec<usize> {
        layout.cores.iter().map(|&(cpu, _)| cpu).collect()
    }

    fn workers_per_node(layout: &PinLayout, workers: u32) -> Vec<usize> {
        layout.per_node(workers).1.into_values().collect()
    }

    /// No node holds more than one worker above another.
    fn assert_balanced(layout: &PinLayout, workers: u32) {
        let counts = workers_per_node(layout, workers);
        let (min, max) = (counts.iter().min().unwrap(), counts.iter().max().unwrap());
        assert!(
            max - min <= 1,
            "{workers} workers pinned unevenly over the nodes: {counts:?}"
        );
    }

    #[test]
    fn cpulists_parse_as_the_kernel_writes_them() {
        assert_eq!(
            parse_cpulist("0-3,8,10-11\n"),
            Some(vec![0, 1, 2, 3, 8, 10, 11])
        );
        assert_eq!(parse_cpulist("5\n"), Some(vec![5]));
        assert_eq!(parse_cpulist("\n"), Some(vec![]), "a memory-only node");
        assert_eq!(parse_cpulist("3-1"), None);
        assert_eq!(parse_cpulist("0-x"), None);
    }

    #[test]
    fn nodes_read_from_sysfs_ignore_other_entries() {
        let root = std::env::temp_dir().join(format!("numa-nodes-{}", std::process::id()));
        for (node, list) in [("node1", "4-7\n"), ("node0", "0-3\n"), ("node2", "\n")] {
            std::fs::create_dir_all(root.join(node)).unwrap();
            std::fs::write(root.join(node).join("cpulist"), list).unwrap();
        }
        std::fs::write(root.join("possible"), "0-2\n").unwrap();
        std::fs::create_dir_all(root.join("power")).unwrap();
        let nodes = read_nodes(&root);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(
            nodes,
            Some(vec![
                (0, vec![0, 1, 2, 3]),
                (1, vec![4, 5, 6, 7]),
                (2, vec![])
            ])
        );
        assert_eq!(read_nodes(&root), None, "no sysfs: no topology");
    }

    #[test]
    fn one_node_or_no_topology_keeps_the_cpu_order() {
        let nodes = contiguous(1, 8);
        let allowed = all(&nodes);
        let layout = PinLayout::new(Some(&nodes), &allowed);
        assert_eq!(cpus(&layout), allowed);
        assert_eq!(layout.order(), "CPU order: one NUMA node");
        assert_eq!(workers_per_node(&layout, 7), vec![7]);

        let layout = PinLayout::new(None, &allowed);
        assert_eq!(cpus(&layout), allowed);
        assert_eq!(layout.order(), "CPU order: NUMA topology unknown");
        assert!(layout.per_node(7).0.is_empty());

        // A CPU the topology does not place: its order cannot be trusted.
        let layout = PinLayout::new(Some(&contiguous(2, 3)), &allowed);
        assert_eq!(cpus(&layout), allowed);
        assert_eq!(layout.order(), "CPU order: NUMA topology unknown");
    }

    #[test]
    fn two_nodes_take_workers_in_turn() {
        let nodes = contiguous(2, 8);
        let layout = PinLayout::new(Some(&nodes), &all(&nodes));
        assert_eq!(&cpus(&layout)[..6], &[0, 8, 1, 9, 2, 10]);
        assert_eq!(layout.order(), "round-robin over NUMA nodes");
        for workers in 1..=15 {
            assert_balanced(&layout, workers);
        }
    }

    /// A peer's host (4 NUMA nodes) ran its workers on the first two nodes,
    /// and node 0 swapped while the others' memory stayed idle.
    #[test]
    fn four_nodes_share_half_a_host_of_workers() {
        let nodes = contiguous(4, 16);
        let layout = PinLayout::new(Some(&nodes), &all(&nodes));
        assert_eq!(
            layout.per_node(0).0.into_values().collect::<Vec<_>>(),
            vec![16; 4]
        );
        for workers in [3, 4, 31, 32, 63] {
            assert_balanced(&layout, workers);
        }
        assert_eq!(workers_per_node(&layout, 31), vec![7, 8, 8, 8]);

        // SMT siblings numbered after every core: each node's cores first.
        let nodes: Vec<(u32, Vec<usize>)> = (0..4)
            .map(|node| {
                let first = node as usize * 8;
                (
                    node,
                    (first..first + 8).chain(32 + first..40 + first).collect(),
                )
            })
            .collect();
        let layout = PinLayout::new(Some(&nodes), &all(&nodes));
        assert_eq!(&cpus(&layout)[..8], &[0, 8, 16, 24, 1, 9, 17, 25]);
        for workers in [5, 31, 63] {
            assert_balanced(&layout, workers);
        }
    }

    #[test]
    fn uneven_nodes_balance_until_the_smaller_fills() {
        let nodes: Vec<(u32, Vec<usize>)> =
            vec![(0, (0..6).collect()), (1, vec![6, 7]), (2, vec![])];
        let layout = PinLayout::new(Some(&nodes), &all(&nodes));
        assert_eq!(cpus(&layout), vec![0, 6, 1, 7, 2, 3, 4, 5]);
        assert_eq!(
            layout.per_node(0).0.len(),
            2,
            "the memory-only node holds no core"
        );
        assert_balanced(&layout, 3);
        assert_eq!(workers_per_node(&layout, 7), vec![5, 2]);
    }

    #[test]
    fn excluded_cpus_are_never_pinned() {
        let nodes = contiguous(2, 8);
        let allowed: Vec<usize> = (2..6).chain(12..14).collect();
        let layout = PinLayout::new(Some(&nodes), &allowed);
        assert_eq!(cpus(&layout), vec![2, 12, 3, 13, 4, 5]);
        assert_eq!(
            layout.per_node(0).0.into_values().collect::<Vec<_>>(),
            vec![4, 2]
        );
        assert_balanced(&layout, 3);

        // A mask within one node is a single-node host.
        let allowed: Vec<usize> = (9..13).collect();
        let layout = PinLayout::new(Some(&nodes), &allowed);
        assert_eq!(cpus(&layout), allowed);
        assert_eq!(layout.order(), "CPU order: one NUMA node");
    }

    #[test]
    fn workers_beyond_the_cpus_run_unpinned() {
        let nodes = contiguous(2, 2);
        let layout = PinLayout::new(Some(&nodes), &all(&nodes));
        assert_eq!(layout.len(), 4);
        assert_eq!(layout.core(3), Some(CoreId { id: 3 }));
        assert_eq!(layout.node(3), Some(1));
        assert_eq!(layout.core(4), None);
        assert_eq!(layout.node(4), None);
        assert_eq!(layout.unpinned(6), 3);
        assert_eq!(layout.unpinned(3), 0);
        assert_eq!(workers_per_node(&layout, 6), vec![1, 2]);
        assert_eq!(PinLayout::new(None, &[]).unpinned(2), 2);
    }

    #[test]
    fn counts_render_by_node() {
        assert_eq!(
            node_counts(&BTreeMap::from([(0, 15), (1, 16)])),
            "0=15 1=16"
        );
    }
}
