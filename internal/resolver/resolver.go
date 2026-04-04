package resolver

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/VojtechPastyrik/muthur-collector/internal/k8s"
	pb "github.com/VojtechPastyrik/muthur-collector/proto"
)

type Resolver struct {
	k8sClient *k8s.Client
	logger    *zap.Logger
}

func New(k8sClient *k8s.Client, logger *zap.Logger) *Resolver {
	return &Resolver{
		k8sClient: k8sClient,
		logger:    logger,
	}
}

func (r *Resolver) Resolve(labels map[string]string) *pb.AlertTarget {
	namespace := labels["namespace"]
	target := &pb.AlertTarget{Namespace: namespace}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. pod label
	if pod, ok := labels["pod"]; ok && pod != "" {
		target.TargetType = "pod"
		target.PodName = pod
		target.ResolvedPods = []string{pod}
		return target
	}

	// 2. deployment label
	if deploy, ok := labels["deployment"]; ok && deploy != "" {
		target.TargetType = "deployment"
		target.Deployment = deploy
		if r.k8sClient != nil {
			pods, err := r.k8sClient.PodsForDeployment(ctx, namespace, deploy)
			if err != nil {
				r.logger.Warn("failed to resolve deployment pods",
					zap.String("deployment", deploy), zap.Error(err))
			} else {
				target.ResolvedPods = limitPods(pods, 10)
			}
		}
		return target
	}

	// 3. daemonset label
	if ds, ok := labels["daemonset"]; ok && ds != "" {
		target.TargetType = "daemonset"
		target.Daemonset = ds
		if r.k8sClient != nil {
			pods, err := r.k8sClient.PodsForDaemonSet(ctx, namespace, ds)
			if err != nil {
				r.logger.Warn("failed to resolve daemonset pods",
					zap.String("daemonset", ds), zap.Error(err))
			} else {
				target.ResolvedPods = limitPods(pods, 10)
			}
		}
		return target
	}

	// 4. statefulset label
	if ss, ok := labels["statefulset"]; ok && ss != "" {
		target.TargetType = "deployment" // treated like deployment for metrics
		target.Deployment = ss
		if r.k8sClient != nil {
			pods, err := r.k8sClient.PodsForStatefulSet(ctx, namespace, ss)
			if err != nil {
				r.logger.Warn("failed to resolve statefulset pods",
					zap.String("statefulset", ss), zap.Error(err))
			} else {
				target.ResolvedPods = limitPods(pods, 10)
			}
		}
		return target
	}

	// 5. node label
	if node, ok := labels["node"]; ok && node != "" {
		target.TargetType = "node"
		target.Node = node
		return target
	}

	// 6. persistentvolumeclaim label
	if pvc, ok := labels["persistentvolumeclaim"]; ok && pvc != "" {
		target.TargetType = "pvc"
		target.Pvc = pvc
		if r.k8sClient != nil {
			pods, err := r.k8sClient.PodsForPVC(ctx, namespace, pvc)
			if err != nil {
				r.logger.Warn("failed to resolve pvc pods",
					zap.String("pvc", pvc), zap.Error(err))
			} else {
				target.ResolvedPods = limitPods(pods, 10)
			}
		}
		return target
	}

	// 7. namespace label only
	if namespace != "" {
		target.TargetType = "namespace"
		return target
	}

	// 8. unknown
	target.TargetType = "unknown"
	r.logger.Warn("could not resolve alert target from labels")
	return target
}

func limitPods(pods []string, max int) []string {
	if len(pods) > max {
		return pods[:max]
	}
	return pods
}
