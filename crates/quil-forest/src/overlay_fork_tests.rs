#[test]
fn overlay_fork_pins_parent_generation_and_survives_its_close() {
    let dir = tempfile::tempdir().unwrap();
    let db = database(dir.path());
    for n in 0..8u8 {
        db.put([0, n], [n]).unwrap();
    }
    let parent = Arc::new(ExecutionOverlay::capture(db.clone(), limits()).unwrap());
    parent
        .apply(&[
            OverlayMutation::DeleteRange(vec![0, 2], vec![0, 5]),
            OverlayMutation::Put(vec![0, 3], vec![30]),
            OverlayMutation::Delete(vec![0, 7]),
        ])
        .unwrap();
    let expected = collect(&parent, false);
    let child = Arc::new(parent.fork(limits()).unwrap());
    db.put([0, 1], [99]).unwrap();
    parent
        .apply(&[OverlayMutation::Put(vec![0, 0], vec![88])])
        .unwrap();
    assert_eq!(collect(&child, false), expected);
    assert_eq!(collect(&child, true), expected);
    let grandchild = child.fork(limits()).unwrap();
    let sibling = parent.fork(limits()).unwrap();
    child
        .apply(&[OverlayMutation::Put(vec![0, 3], vec![31])])
        .unwrap();
    assert_eq!(grandchild.get(&[0, 3]).unwrap(), Some(vec![30]));
    assert_eq!(sibling.get(&[0, 0]).unwrap(), Some(vec![88]));
    let sequence = db.latest_sequence_number();
    parent.close();
    child.close();
    assert!(parent.fork(limits()).is_err());
    assert!(child.get(&[0, 3]).is_err());
    assert_eq!(collect(&grandchild, false), expected);
    grandchild
        .apply(&[OverlayMutation::Put(vec![0, 6], vec![60])])
        .unwrap();
    assert_eq!(db.get([0, 6]).unwrap(), Some(vec![6]));
    assert_eq!(db.latest_sequence_number(), sequence);
    grandchild.close();
    sibling.close();
}

#[test]
fn overlay_fork_family_admission_counts_closed_branches_and_retained_views() {
    let dir = tempfile::tempdir().unwrap();
    let root_limits = OverlayLimits {
        max_cursors: 2,
        ..limits()
    };
    let root = ExecutionOverlay::capture(database(dir.path()), root_limits).unwrap();
    let child = Arc::new(root.fork(root_limits).unwrap());
    let view = child.read_view().unwrap();
    let grandchild = child.fork(root_limits).unwrap();
    assert_eq!(root.stats().descendant_branches, 2);
    assert!(root.fork(root_limits).is_err());
    assert!(grandchild.fork(root_limits).is_err());
    child.close();
    drop(child);
    assert!(
        root.fork(root_limits).is_err(),
        "a closed branch's read view still retains its delta"
    );
    assert!(view.get(b"anything").is_err());
    drop(view);
    assert_eq!(root.stats().descendant_branches, 1);
    let sibling = root.fork(root_limits).unwrap();
    assert_eq!(root.stats().descendant_branches, 2);
    drop(grandchild);
    drop(sibling);
    assert_eq!(root.stats().descendant_branches, 0);
}

#[test]
fn overlay_fork_enforces_inherited_delta_and_nonincreasing_limits() {
    let dir = tempfile::tempdir().unwrap();
    let root = ExecutionOverlay::capture(database(dir.path()), limits()).unwrap();
    root.apply(&[OverlayMutation::Put(b"key".to_vec(), vec![1; 12])])
        .unwrap();
    for invalid in [
        OverlayLimits {
            max_delta_bytes: 14,
            ..limits()
        },
        OverlayLimits {
            max_delta_entries: 0,
            ..limits()
        },
        OverlayLimits {
            max_record_bytes: 14,
            ..limits()
        },
        OverlayLimits {
            max_read_operations: 0,
            ..limits()
        },
        OverlayLimits {
            max_cursors: 5,
            ..limits()
        },
        OverlayLimits {
            max_read_bytes: limits().max_read_bytes + 1,
            ..limits()
        },
    ] {
        assert!(root.fork(invalid).is_err());
        assert_eq!(root.stats().descendant_branches, 0);
    }
    let child = root
        .fork(OverlayLimits {
            max_delta_bytes: 15,
            max_delta_entries: 1,
            ..limits()
        })
        .unwrap();
    assert_eq!(child.get(b"key").unwrap(), Some(vec![1; 12]));
    assert!(child
        .apply(&[OverlayMutation::Put(b"extra".to_vec(), vec![2])])
        .is_err());
    assert_eq!(child.get(b"extra").unwrap(), None);
    assert_eq!(root.get(b"key").unwrap(), Some(vec![1; 12]));
}
