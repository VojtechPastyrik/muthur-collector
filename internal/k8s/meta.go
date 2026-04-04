package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

func (c *Client) PodMeta(ctx context.Context, namespace, podName string) (*pb.PodMeta, error) {
	pod, err := c.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s: %w", podName, err)
	}

	meta := &pb.PodMeta{
		PodName:  pod.Name,
		NodeName: pod.Spec.NodeName,
		Phase:    string(pod.Status.Phase),
	}

	if len(pod.Spec.Containers) > 0 {
		container := pod.Spec.Containers[0]
		if lim := container.Resources.Limits; lim != nil {
			if mem, ok := lim["memory"]; ok {
				meta.MemoryLimit = mem.String()
			}
			if cpu, ok := lim["cpu"]; ok {
				meta.CpuLimit = cpu.String()
			}
		}
		if req := container.Resources.Requests; req != nil {
			if mem, ok := req["memory"]; ok {
				meta.MemoryRequest = mem.String()
			}
			if cpu, ok := req["cpu"]; ok {
				meta.CpuRequest = cpu.String()
			}
		}
	}

	if len(pod.Status.ContainerStatuses) > 0 {
		meta.RestartCount = pod.Status.ContainerStatuses[0].RestartCount
	}

	return meta, nil
}
