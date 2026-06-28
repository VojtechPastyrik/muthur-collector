package auth

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// SecretStore persists the collector's mTLS material into a Kubernetes
// Secret rather than into a PersistentVolumeClaim. The main container
// mounts the Secret normally; the kubelet projects updates as the Secret
// changes, and ClientReloader picks the new files up via its mtime watch.
//
// Why a Secret rather than a PVC: Secrets are the native primitive for cert
// material in Kubernetes, they don't depend on storage classes, and they
// work the same way cert-manager wires its own Certificate Secrets — so the
// behaviour is familiar to operators and there is no extra moving part.
type SecretStore struct {
	clientset  kubernetes.Interface
	namespace  string
	secretName string
}

// SecretKeys are the well-known keys inside the cert Secret. They match
// cert-manager's layout (tls.crt/tls.key/ca.crt) so any tooling that already
// understands cert-manager Secrets understands this one too.
const (
	SecretKeyCert = "tls.crt"
	SecretKeyKey  = "tls.key"
	SecretKeyCA   = "ca.crt"
)

// NewSecretStoreInCluster builds a SecretStore using the in-cluster
// ServiceAccount credentials. Returns an error when the binary is not
// running in a pod (e.g. local development) — those flows should use the
// file-based Material instead.
//
// The created Secret intentionally carries NO app.kubernetes.io/instance
// label and NO argocd.argoproj.io/tracking-id annotation, so ArgoCD does
// not claim ownership and never reports the Secret as OutOfSync.
func NewSecretStoreInCluster(namespace, secretName string) (*SecretStore, error) {
	if namespace == "" {
		return nil, errors.New("auth: namespace is required for SecretStore")
	}
	if secretName == "" {
		return nil, errors.New("auth: secretName is required for SecretStore")
	}
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes clientset: %w", err)
	}
	return &SecretStore{clientset: cs, namespace: namespace, secretName: secretName}, nil
}

// Exists reports whether the Secret already carries a non-empty cert + key.
// Bootstrap uses this for its idempotency check — re-running bootstrap after
// a pod restart must NOT burn a fresh token if the cert is already there.
func (s *SecretStore) Exists(ctx context.Context) (bool, error) {
	sec, err := s.clientset.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get secret: %w", err)
	}
	return len(sec.Data[SecretKeyCert]) > 0 && len(sec.Data[SecretKeyKey]) > 0, nil
}

// Read returns the current cert+key+CA bundle. Used by renewal to load the
// existing leaf for the mTLS handshake against /sign-csr.
func (s *SecretStore) Read(ctx context.Context) (cert, key, ca []byte, err error) {
	sec, err := s.clientset.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get secret: %w", err)
	}
	return sec.Data[SecretKeyCert], sec.Data[SecretKeyKey], sec.Data[SecretKeyCA], nil
}

// Write creates or updates the Secret with the given material. cert and key
// are required; an empty ca keeps the previously stored CA, which matches
// the renewal flow where the CA usually does not change.
func (s *SecretStore) Write(ctx context.Context, cert, key, ca []byte) error {
	if len(cert) == 0 || len(key) == 0 {
		return errors.New("auth: cert and key are required")
	}

	api := s.clientset.CoreV1().Secrets(s.namespace)
	existing, err := api.Get(ctx, s.secretName, metav1.GetOptions{})
	switch {
	case err == nil:
		data := map[string][]byte{
			SecretKeyCert: cert,
			SecretKeyKey:  key,
		}
		if len(ca) > 0 {
			data[SecretKeyCA] = ca
		} else if existingCA := existing.Data[SecretKeyCA]; len(existingCA) > 0 {
			data[SecretKeyCA] = existingCA
		}
		existing.Type = corev1.SecretTypeTLS
		existing.Data = data
		_, err := api.Update(ctx, existing, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("update secret: %w", err)
		}
	case apierrors.IsNotFound(err):
		data := map[string][]byte{
			SecretKeyCert: cert,
			SecretKeyKey:  key,
		}
		if len(ca) > 0 {
			data[SecretKeyCA] = ca
		}
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.secretName,
				Namespace: s.namespace,
				// Belt-and-braces guard against `argocd app sync --prune`
				// or `helm uninstall` from removing the cert. The Secret
				// is invisible to ArgoCD's tracking (no instance label,
				// no tracking-id), but operators sometimes target the
				// namespace explicitly — these annotations make the
				// no-prune contract explicit.
				Annotations: map[string]string{
					"argocd.argoproj.io/sync-options": "Prune=false",
					"helm.sh/resource-policy":         "keep",
				},
			},
			Type: corev1.SecretTypeTLS,
			Data: data,
		}
		if _, err := api.Create(ctx, sec, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create secret: %w", err)
		}
	default:
		return fmt.Errorf("get secret: %w", err)
	}
	return nil
}
