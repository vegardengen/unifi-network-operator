package config

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type OperatorConfig struct {
	DefaultNamespace string
}

type ConfigLoader struct {
	Client    client.Client
	Name      string
	Namespace string
}

func New(client client.Client, name, namespace string) *ConfigLoader {
	return &ConfigLoader{
		Client:    client,
		Name:      name,
		Namespace: namespace,
	}
}

func (cl *ConfigLoader) Load(ctx context.Context) (*OperatorConfig, error) {
	cm := &corev1.ConfigMap{}
	err := cl.Client.Get(ctx, types.NamespacedName{
		Name:      cl.Name,
		Namespace: cl.Namespace,
	}, cm)
	if err != nil {
		return nil, fmt.Errorf("failed to load configmap: %w", err)
	}

	cfg := &OperatorConfig{
		DefaultNamespace: "default", // fallback
	}

	if val, ok := cm.Data["defaultNamespace"]; ok && val != "" {
		cfg.DefaultNamespace = val
	}

	return cfg, nil
}

