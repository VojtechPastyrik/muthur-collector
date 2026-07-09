package k8s

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

// maxEventsPerObject caps events per involved object so a crash-looping pod
// with hundreds of repeated events cannot bloat the payload past the
// forwarder size guard.
const maxEventsPerObject = 25

// FetchEvents lists Kubernetes events for a single object (pod, PVC, ...) in
// the namespace, newest first. Scheduling and lifecycle failures such as
// FailedScheduling, FailedMount or ImagePullBackOff surface only here — a pod
// that never started has no logs.
func (c *Client) FetchEvents(ctx context.Context, namespace, objectName string) ([]*pb.KubernetesEvent, error) {
	list, err := c.clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + objectName,
	})
	if err != nil {
		return nil, fmt.Errorf("list events for %s: %w", objectName, err)
	}

	events := make([]*pb.KubernetesEvent, 0, len(list.Items))
	for i := range list.Items {
		ev := &list.Items[i]
		// The API server already filters via the field selector; this guard
		// keeps behaviour identical under fakes and older servers.
		if ev.InvolvedObject.Name != objectName {
			continue
		}

		first := ev.FirstTimestamp.Unix()
		last := ev.LastTimestamp.Unix()
		count := ev.Count
		// Newer API servers populate eventTime/series instead of the
		// deprecated firstTimestamp/lastTimestamp/count trio.
		if ev.FirstTimestamp.IsZero() {
			first = ev.EventTime.Unix()
		}
		if ev.LastTimestamp.IsZero() {
			if ev.Series != nil {
				last = ev.Series.LastObservedTime.Unix()
				count = ev.Series.Count
			} else {
				last = ev.EventTime.Unix()
			}
		}
		if first < 0 {
			first = 0
		}
		if last < 0 {
			last = 0
		}
		if count == 0 {
			count = 1
		}

		events = append(events, &pb.KubernetesEvent{
			Type:               ev.Type,
			Reason:             ev.Reason,
			Message:            ev.Message,
			FirstTimestamp:     first,
			LastTimestamp:      last,
			Count:              count,
			InvolvedObjectName: objectName,
		})
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].LastTimestamp > events[j].LastTimestamp
	})
	if len(events) > maxEventsPerObject {
		events = events[:maxEventsPerObject]
	}
	return events, nil
}
