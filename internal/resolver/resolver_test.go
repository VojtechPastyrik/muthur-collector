package resolver

import (
	"testing"

	"go.uber.org/zap"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

func TestResolve_Pod(t *testing.T) {
	r := New(nil, zap.NewNop())
	target := r.Resolve(map[string]string{
		"namespace": "default",
		"pod":       "my-pod",
	})
	assertTarget(t, target, "pod", "my-pod", []string{"my-pod"})
}

func TestResolve_Deployment(t *testing.T) {
	// Without k8s client, deployment resolution will have empty pods
	r := New(nil, zap.NewNop())
	target := r.Resolve(map[string]string{
		"namespace":  "default",
		"deployment": "my-deploy",
	})
	if target.TargetType != "deployment" {
		t.Errorf("expected deployment, got %s", target.TargetType)
	}
	if target.Deployment != "my-deploy" {
		t.Errorf("expected my-deploy, got %s", target.Deployment)
	}
}

func TestResolve_DaemonSet(t *testing.T) {
	r := New(nil, zap.NewNop())
	target := r.Resolve(map[string]string{
		"namespace": "kube-system",
		"daemonset": "node-exporter",
	})
	if target.TargetType != "daemonset" {
		t.Errorf("expected daemonset, got %s", target.TargetType)
	}
	if target.Daemonset != "node-exporter" {
		t.Errorf("expected node-exporter, got %s", target.Daemonset)
	}
}

func TestResolve_Node(t *testing.T) {
	r := New(nil, zap.NewNop())
	target := r.Resolve(map[string]string{
		"node": "node-01",
	})
	if target.TargetType != "node" {
		t.Errorf("expected node, got %s", target.TargetType)
	}
	if target.Node != "node-01" {
		t.Errorf("expected node-01, got %s", target.Node)
	}
}

func TestResolve_PVC(t *testing.T) {
	r := New(nil, zap.NewNop())
	target := r.Resolve(map[string]string{
		"namespace":             "default",
		"persistentvolumeclaim": "data-pvc",
	})
	if target.TargetType != "pvc" {
		t.Errorf("expected pvc, got %s", target.TargetType)
	}
	if target.Pvc != "data-pvc" {
		t.Errorf("expected data-pvc, got %s", target.Pvc)
	}
}

func TestResolve_Namespace(t *testing.T) {
	r := New(nil, zap.NewNop())
	target := r.Resolve(map[string]string{
		"namespace": "monitoring",
	})
	if target.TargetType != "namespace" {
		t.Errorf("expected namespace, got %s", target.TargetType)
	}
}

func TestResolve_Unknown(t *testing.T) {
	r := New(nil, zap.NewNop())
	target := r.Resolve(map[string]string{})
	if target.TargetType != "unknown" {
		t.Errorf("expected unknown, got %s", target.TargetType)
	}
}

func TestResolve_PriorityOrder(t *testing.T) {
	// Pod takes priority over deployment
	r := New(nil, zap.NewNop())
	target := r.Resolve(map[string]string{
		"namespace":  "default",
		"pod":        "my-pod",
		"deployment": "my-deploy",
	})
	if target.TargetType != "pod" {
		t.Errorf("pod should take priority, got %s", target.TargetType)
	}
}

func TestLimitPods(t *testing.T) {
	pods := make([]string, 20)
	for i := range pods {
		pods[i] = "pod-" + string(rune('a'+i))
	}

	limited := limitPods(pods, 10)
	if len(limited) != 10 {
		t.Errorf("expected 10 pods, got %d", len(limited))
	}

	small := []string{"a", "b"}
	limited = limitPods(small, 10)
	if len(limited) != 2 {
		t.Errorf("expected 2 pods, got %d", len(limited))
	}
}

func assertTarget(t *testing.T, target *pb.AlertTarget, expectedType, expectedPod string, expectedPods []string) {
	t.Helper()
	if target.TargetType != expectedType {
		t.Errorf("expected type %s, got %s", expectedType, target.TargetType)
	}
	if target.PodName != expectedPod {
		t.Errorf("expected pod %s, got %s", expectedPod, target.PodName)
	}
	if len(target.ResolvedPods) != len(expectedPods) {
		t.Errorf("expected %d resolved pods, got %d", len(expectedPods), len(target.ResolvedPods))
	}
}
