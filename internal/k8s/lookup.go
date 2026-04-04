package k8s

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (c *Client) PodsForDeployment(ctx context.Context, namespace, name string) ([]string, error) {
	deploy, err := c.clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get deployment %s: %w", name, err)
	}

	selector, err := metav1.LabelSelectorAsSelector(deploy.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("parse selector: %w", err)
	}

	return c.podNamesBySelector(ctx, namespace, selector)
}

func (c *Client) PodsForDaemonSet(ctx context.Context, namespace, name string) ([]string, error) {
	ds, err := c.clientset.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get daemonset %s: %w", name, err)
	}

	selector, err := metav1.LabelSelectorAsSelector(ds.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("parse selector: %w", err)
	}

	return c.podNamesBySelector(ctx, namespace, selector)
}

func (c *Client) PodsForStatefulSet(ctx context.Context, namespace, name string) ([]string, error) {
	ss, err := c.clientset.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get statefulset %s: %w", name, err)
	}

	selector, err := metav1.LabelSelectorAsSelector(ss.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("parse selector: %w", err)
	}

	return c.podNamesBySelector(ctx, namespace, selector)
}

func (c *Client) PodsForPVC(ctx context.Context, namespace, pvcName string) ([]string, error) {
	pods, err := c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	var result []string
	for _, pod := range pods.Items {
		for _, vol := range pod.Spec.Volumes {
			if vol.PersistentVolumeClaim != nil && vol.PersistentVolumeClaim.ClaimName == pvcName {
				result = append(result, pod.Name)
				break
			}
		}
	}
	return result, nil
}

func (c *Client) podNamesBySelector(ctx context.Context, namespace string, selector labels.Selector) ([]string, error) {
	pods, err := c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	names := make([]string, 0, len(pods.Items))
	for _, pod := range pods.Items {
		names = append(names, pod.Name)
	}
	return names, nil
}
