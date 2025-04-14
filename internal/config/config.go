package config

import (
	"context"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ConfigLoaderType struct {
	Client client.Client

	mu     sync.Mutex
	loaded bool
	config *corev1.ConfigMap
	err    error
}

func NewConfigLoader(k8sClient client.Client) *ConfigLoaderType {
	return &ConfigLoaderType{Client: k8sClient}
}

func (c *ConfigLoaderType) GetConfig(ctx context.Context, name string) (*corev1.ConfigMap, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.loaded {
		return c.config, c.err
	}

	cm := &corev1.ConfigMap{}
	err := c.Client.Get(ctx, types.NamespacedName{
		Name:      name,
		Namespace: "unifi-network-operator-system",
	}, cm)

	c.loaded = true
	c.config = cm
	c.err = err

	return cm, err
}
