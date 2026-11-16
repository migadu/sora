package imap

import (
	"testing"

	"github.com/migadu/go-imap"
)

func TestDiffNotifyAffectedUnicodeAndIndependentChanges(t *testing.T) {
	prev := map[int64]notifySnapshotEntry{
		1: {name: "Ångström"},
		2: {name: "ångström/子"},
		3: {name: "Ångström/独"},
		4: {name: "Archive"},
	}
	cur := map[int64]notifySnapshotEntry{
		1: {name: "Archive/Ångström"},
		2: {name: "Archive/Ångström/子", subscribed: true},
		3: {name: "Detached"},
		4: {name: "Archive"},
	}
	events := diffNotifySnapshots(prev, cur)
	got := make(map[string]notifyTreeEvent)
	for _, ev := range events {
		got[ev.name] = ev
	}
	if len(events) != 3 {
		t.Fatalf("events: %+v", events)
	}
	if ev := got["Archive/Ångström"]; ev.event != imap.NotifyEventMailboxName || ev.oldName != "Ångström" || !ev.hasChildren {
		t.Errorf("superior: %+v", ev)
	}
	if ev := got["Archive/Ångström/子"]; ev.event != imap.NotifyEventSubscriptionChange || !ev.entry.subscribed {
		t.Errorf("carried subscription: %+v", ev)
	}
	if ev := got["Detached"]; ev.event != imap.NotifyEventMailboxName || ev.oldName != "Ångström/独" {
		t.Errorf("independent child: %+v", ev)
	}
}

func TestDiffNotifyParentStoredCaseAndInaccessibleUnicode(t *testing.T) {
	t.Run("stored parent case and remaining children", func(t *testing.T) {
		prev := map[int64]notifySnapshotEntry{1: {name: "MiXeD", subscribed: true}, 2: {name: "mixed/旧"}}
		cur := map[int64]notifySnapshotEntry{1: {name: "MiXeD", subscribed: true}, 3: {name: "MIXED/新"}}
		var parent *notifyTreeEvent
		for _, ev := range diffNotifySnapshots(prev, cur) {
			if ev.name == "MiXeD" {
				copy := ev
				parent = &copy
			}
		}
		if parent == nil || parent.deleted || !parent.hasChildren || !parent.entry.subscribed {
			t.Fatalf("parent: %+v", parent)
		}
	})
	t.Run("missing parent remains nonexistent with children", func(t *testing.T) {
		var parent *notifyTreeEvent
		for _, ev := range diffNotifySnapshots(nil, map[int64]notifySnapshotEntry{1: {name: "不可視/子"}}) {
			if ev.name == "不可視" {
				copy := ev
				parent = &copy
			}
		}
		if parent == nil || !parent.deleted || !parent.hasChildren {
			t.Fatalf("parent: %+v", parent)
		}
	})
}
