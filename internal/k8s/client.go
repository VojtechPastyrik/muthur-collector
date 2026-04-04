package k8s

import (
	"fmt"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Client struct {
	clientset *kubernetes.Clientset
	logger    *zap.Logger
}

func NewClient(logger *zap.Logger) (*Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create clientset: %w", err)
	}

	return &Client{clientset: clientset, logger: logger}, nil
}

// NewClientFromClientset creates a Client from an existing clientset (for testing).
func NewClientFromClientset(cs *kubernetes.Clientset, logger *zap.Logger) *Client {
	return &Client{clientset: cs, logger: logger}
}
