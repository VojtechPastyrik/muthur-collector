package k8s

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func event(name, objName, reason, msg string, ts time.Time, count int32) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		InvolvedObject: corev1.ObjectReference{
			Kind:      "Pod",
			Name:      objName,
			Namespace: "default",
		},
		Type:           corev1.EventTypeWarning,
		Reason:         reason,
		Message:        msg,
		FirstTimestamp: metav1.NewTime(ts),
		LastTimestamp:  metav1.NewTime(ts),
		Count:          count,
	}
}

func TestFetchEvents_ReturnsEventsForObject(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		event("e1", "app-123", "FailedScheduling", "0/3 nodes available: pod has unbound immediate PersistentVolumeClaims", now, 3),
		event("e2", "other-pod", "Pulled", "image pulled", now, 1),
	)
	c := NewClientFromClientset(cs, zap.NewNop())

	events, err := c.FetchEvents(context.Background(), "default", "app-123")
	if err != nil {
		t.Fatalf("FetchEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Reason != "FailedScheduling" {
		t.Errorf("reason = %q, want FailedScheduling", ev.Reason)
	}
	if ev.Count != 3 {
		t.Errorf("count = %d, want 3", ev.Count)
	}
	if ev.InvolvedObjectName != "app-123" {
		t.Errorf("involved object = %q, want app-123", ev.InvolvedObjectName)
	}
	if ev.LastTimestamp != now.Unix() {
		t.Errorf("last timestamp = %d, want %d", ev.LastTimestamp, now.Unix())
	}
}

func TestFetchEvents_SortedNewestFirstAndCapped(t *testing.T) {
	base := time.Now().Add(-time.Hour)
	var objs []*corev1.Event
	for i := 0; i < maxEventsPerObject+10; i++ {
		objs = append(objs, event(
			fmt.Sprintf("e%d", i), "app-123", "BackOff", "back-off restarting container",
			base.Add(time.Duration(i)*time.Minute), 1,
		))
	}
	cs := fake.NewSimpleClientset()
	for _, o := range objs {
		if _, err := cs.CoreV1().Events("default").Create(context.Background(), o, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	c := NewClientFromClientset(cs, zap.NewNop())

	events, err := c.FetchEvents(context.Background(), "default", "app-123")
	if err != nil {
		t.Fatalf("FetchEvents: %v", err)
	}
	if len(events) != maxEventsPerObject {
		t.Fatalf("expected cap %d, got %d", maxEventsPerObject, len(events))
	}
	for i := 1; i < len(events); i++ {
		if events[i-1].LastTimestamp < events[i].LastTimestamp {
			t.Fatalf("events not sorted newest first at index %d", i)
		}
	}
}

func TestFetchEvents_SeriesFallback(t *testing.T) {
	observed := time.Now()
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Name: "e-series", Namespace: "default"},
		InvolvedObject: corev1.ObjectReference{
			Kind: "Pod", Name: "app-123", Namespace: "default",
		},
		Type:      corev1.EventTypeWarning,
		Reason:    "FailedMount",
		Message:   "MountVolume.SetUp failed",
		EventTime: metav1.NewMicroTime(observed),
		Series: &corev1.EventSeries{
			Count:            7,
			LastObservedTime: metav1.NewMicroTime(observed),
		},
	}
	cs := fake.NewSimpleClientset(ev)
	c := NewClientFromClientset(cs, zap.NewNop())

	events, err := c.FetchEvents(context.Background(), "default", "app-123")
	if err != nil {
		t.Fatalf("FetchEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Count != 7 {
		t.Errorf("count = %d, want 7 from series", events[0].Count)
	}
	if events[0].LastTimestamp != observed.Unix() {
		t.Errorf("last timestamp = %d, want %d", events[0].LastTimestamp, observed.Unix())
	}
}
