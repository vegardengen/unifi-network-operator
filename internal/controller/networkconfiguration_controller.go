/*
Copyright 2025 Vegard Engen.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	unifiv1 "github.com/vegardengen/unifi-network-operator/api/v1beta1"
	"github.com/vegardengen/unifi-network-operator/internal/unifi"
	"github.com/vegardengen/unifi-network-operator/internal/config"
)

// NetworkconfigurationReconciler reconciles a Networkconfiguration object
type NetworkconfigurationReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	UnifiClient *unifi.UnifiClient
	ConfigLoader *config.ConfigLoaderType
}

// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=networkconfigurations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=networkconfigurations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=networkconfigurations/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=list;get

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Networkconfiguration object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *NetworkconfigurationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	cfg, err := r.ConfigLoader.GetConfig(ctx, "unifi-operator-config")
        if err != nil {
            return ctrl.Result{}, err
        }

        defaultNs := cfg.Data["defaultNamespace"]
	log.Info(defaultNs)

	var networkCRDs unifiv1.NetworkconfigurationList
	if err := r.List(ctx, &networkCRDs); err != nil {
		return ctrl.Result{}, err
	}
	k8sNetworks := make(map[string]*unifiv1.Networkconfiguration)
	for i := range networkCRDs.Items {
		log.Info(fmt.Sprintf("Inserting network %s\n", networkCRDs.Items[i].Spec.NetworkID))
		k8sNetworks[networkCRDs.Items[i].Spec.NetworkID] = &networkCRDs.Items[i]
	}

	networks, err := r.UnifiClient.Client.ListNetwork(context.Background(), r.UnifiClient.SiteID)
	if err != nil {
		log.Error(err, "Failed to list Unifi Networks")
		return ctrl.Result{}, err
	}

	seenNetworks := map[string]bool{}

	for _, network := range networks {
		networkID := network.ID
		seenNetworks[networkID] = true
		log.Info(fmt.Sprintf("Searching for  %s\n", networkID))

		if existing, found := k8sNetworks[networkID]; found {
			log.Info(fmt.Sprintf("Found network match: %s/%s", existing.Spec.NetworkID, networkID))
		} else {
			if network.Purpose == "corporate" {
				log.Info(fmt.Sprintf("New network: %s with ID %s", network.Name, network.ID))
				var networkObject unifiv1.Networkconfiguration
				networkObject.Name = network.Name
				networkObject.Spec.Name = network.Name
				networkObject.Spec.NetworkID = network.ID
				networkObject.Spec.IPSubnet = network.IPSubnet
				networkObject.Spec.Ipv6InterfaceType = network.IPV6InterfaceType
				networkObject.Spec.Ipv6PdAutoPrefixidEnabled = network.IPV6PDAutoPrefixidEnabled
				networkObject.Spec.Ipv6RaEnabled = network.IPV6RaEnabled
				networkObject.Spec.Ipv6SettingPreference = network.IPV6SettingPreference
				networkObject.Spec.Ipv6Subnet = network.IPV6Subnet
				networkObject.Spec.Purpose = network.Purpose
				networkObject.Spec.Networkgroup = network.NetworkGroup
				networkObject.Spec.SettingPreference = network.SettingPreference
				networkObject.Spec.VlanEnabled = network.VLANEnabled
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkconfigurationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&unifiv1.Networkconfiguration{}).
		Named("networkconfiguration").
		Complete(r)
}
