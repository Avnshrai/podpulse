// Package k8s wraps the slice of client-go that PodPulse needs:
// in-cluster + kubeconfig client construction, plus shared informers
// for Pods and ReplicaSets that drive the pod-metadata cache and the
// rollout cache.
package k8s

import (
	"errors"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClient returns a Kubernetes clientset using, in order of preference:
//  1. An explicit kubeconfig path (the kubeconfigPath arg or $KUBECONFIG).
//  2. In-cluster configuration (when running as a pod).
//  3. ~/.kube/config (developer fallback).
func NewClient(kubeconfigPath string) (*kubernetes.Clientset, error) {
	cfg, err := loadConfig(kubeconfigPath)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func loadConfig(kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath == "" {
		kubeconfigPath = os.Getenv("KUBECONFIG")
	}
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	} else if !errors.Is(err, rest.ErrNotInCluster) {
		return nil, err
	}
	if home, err := os.UserHomeDir(); err == nil {
		def := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(def); err == nil {
			return clientcmd.BuildConfigFromFlags("", def)
		}
	}
	return nil, errors.New("no kubeconfig found and not running in cluster")
}
