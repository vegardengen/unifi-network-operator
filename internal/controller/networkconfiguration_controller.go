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
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	unifiv1 "github.com/vegardengen/unifi-network-operator/api/v1beta1"
	"github.com/vegardengen/unifi-network-operator/internal/config"
	"github.com/vegardengen/unifi-network-operator/internal/unifi"
)

// NetworkconfigurationReconciler reconciles a Networkconfiguration object
type NetworkconfigurationReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	UnifiClient  *unifi.UnifiClient
	ConfigLoader *config.ConfigLoaderType
}

// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=networkconfigurations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=networkconfigurations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=networkconfigurations/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=list;get;watch

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

	fullSyncNetwork := "core"
	if cfg.Data["fullSyncNetwork"] != "" {
		fullSyncNetwork = cfg.Data["fullSyncNetwork"]
	}

	fullSync := false
	var networkObj unifiv1.Networkconfiguration
	if err := r.Get(ctx, req.NamespacedName, &networkObj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info(fmt.Sprintf("fullSyncNetwork: %s Network: %s", fullSyncNetwork, networkObj.Name))
	if networkObj.Name == fullSyncNetwork {
		fullSync = true
		log.Info("Going into fullsync mode")
	}

	err = r.UnifiClient.Reauthenticate()
	if err != nil {
		return ctrl.Result{}, err
	}

	if !fullSync {
		networks, err := r.UnifiClient.Client.ListNetwork(context.Background(), r.UnifiClient.SiteID)
		if err != nil {
			log.Error(err, "Could not list netwrorks")
			return ctrl.Result{}, err
		}
		found := false
		for _, unifinetwork := range networks {
			if unifinetwork.Name == networkObj.Spec.Name {
				found = true
				networkSpec := unifiv1.NetworkconfigurationSpec{
					Name:                      unifinetwork.Name,
					ID:                        unifinetwork.ID,
					IPSubnet:                  unifinetwork.IPSubnet,
					Ipv6InterfaceType:         unifinetwork.IPV6InterfaceType,
					Ipv6PdAutoPrefixidEnabled: unifinetwork.IPV6PDAutoPrefixidEnabled,
					Ipv6RaEnabled:             unifinetwork.IPV6RaEnabled,
					Ipv6SettingPreference:     unifinetwork.IPV6SettingPreference,
					Ipv6Subnet:                unifinetwork.IPV6Subnet,
					Purpose:                   unifinetwork.Purpose,
					Networkgroup:              unifinetwork.NetworkGroup,
					SettingPreference:         unifinetwork.SettingPreference,
					Vlan:                      int64(unifinetwork.VLAN),
					VlanEnabled:               unifinetwork.VLANEnabled,
				}
				if !reflect.DeepEqual(networkObj.Spec, networkSpec) {
					networkObj.Spec = networkSpec
					err := r.Update(ctx, &networkObj)
					if err != nil {
						return ctrl.Result{}, err
					}
				}
			}
		}
		if !found {
			err := r.Delete(ctx, &networkObj)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	log.Info("Starting fullsync mode")
	var networkCRDs unifiv1.NetworkconfigurationList
	_ = r.List(ctx, &networkCRDs, client.InNamespace(defaultNs))

	networks, err := r.UnifiClient.Client.ListNetwork(context.Background(), r.UnifiClient.SiteID)
	if err != nil {
		log.Error(err, "Could not list netwrorks")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}
	log.Info(fmt.Sprintf("Number of resources: %d Number of networks in Unifi: %d", len(networkCRDs.Items), len(networks)))

	var firewallZoneCRDs unifiv1.FirewallZoneList
	err = r.List(ctx, &firewallZoneCRDs, client.InNamespace(defaultNs))
	if err != nil {
		log.Error(err, "Could not list firewall zones")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}

	networkNamesUnifi := make(map[string]struct{})
	for _, unifinetwork := range networks {
		networkNamesUnifi[unifinetwork.Name] = struct{}{}
	}

	// Step 2: Collect zones in fwzCRDs that are NOT in firewall_zones
	for _, network := range networkCRDs.Items {
		if _, found := networkNamesUnifi[network.Spec.Name]; !found {
			err := r.Delete(ctx, &network)
			if err != nil {
				return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
			}
		}
	}
	networkNamesCRDs := make(map[string]struct{})
	for _, networkCRD := range networkCRDs.Items {
		networkNamesCRDs[networkCRD.Spec.Name] = struct{}{}
	}
	for _, unifinetwork := range networks {
		if unifinetwork.Purpose == "corporate" {
			networkSpec := unifiv1.NetworkconfigurationSpec{
				Name:                      unifinetwork.Name,
				ID:                        unifinetwork.ID,
				IPSubnet:                  unifinetwork.IPSubnet,
				Ipv6InterfaceType:         unifinetwork.IPV6InterfaceType,
				Ipv6PdAutoPrefixidEnabled: unifinetwork.IPV6PDAutoPrefixidEnabled,
				Ipv6RaEnabled:             unifinetwork.IPV6RaEnabled,
				Ipv6SettingPreference:     unifinetwork.IPV6SettingPreference,
				Ipv6Subnet:                unifinetwork.IPV6Subnet,
				Purpose:                   unifinetwork.Purpose,
				Networkgroup:              unifinetwork.NetworkGroup,
				SettingPreference:         unifinetwork.SettingPreference,
				Vlan:                      int64(unifinetwork.VLAN),
				VlanEnabled:               unifinetwork.VLANEnabled,
			}
			networkStatus := unifiv1.NetworkconfigurationStatus{
				FirewallZoneID: unifinetwork.FirewallZoneID,
			}
			log.Info(fmt.Sprintf("Network status %s: %+v", networkSpec.Name, networkStatus))
			if _, found := networkNamesCRDs[unifinetwork.Name]; !found {
				firewallZoneNamesCRDs := make(map[string]struct{})
				firewallZoneIdsCRDs := make(map[string]struct{})
				for _, firewallZoneCRD := range firewallZoneCRDs.Items {
					firewallZoneNamesCRDs[firewallZoneCRD.Spec.Name] = struct{}{}
					firewallZoneIdsCRDs[firewallZoneCRD.Spec.ID] = struct{}{}
				}
				networkCRD := &unifiv1.Networkconfiguration{
					ObjectMeta: ctrl.ObjectMeta{
						Name:      toKubeName(unifinetwork.Name),
						Namespace: defaultNs,
					},
					Spec:   networkSpec,
					Status: networkStatus,
				}
				err = r.Create(ctx, networkCRD)
				if err != nil {
					return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
				}
				err = r.Get(ctx, types.NamespacedName{Name: networkCRD.Name, Namespace: networkCRD.Namespace}, networkCRD)
				networkCRD.Status = networkStatus
				if err = r.Status().Update(ctx, networkCRD); err != nil {
					return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
				}
			} else {
				for _, networkCRD := range networkCRDs.Items {
					if networkCRD.Spec.Name == unifinetwork.Name {
						if !reflect.DeepEqual(networkCRD.Spec, networkSpec) {
							networkCRD.Spec = networkSpec
							err := r.Update(ctx, &networkCRD)
							if err != nil {
								return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
							}
						}
						if !reflect.DeepEqual(networkCRD.Status, networkStatus) {
							networkCRD.Status = networkStatus
							if err = r.Status().Update(ctx, &networkCRD); err != nil {
								return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
							}
						}
					}
				}
			}
		}
	}

	return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkconfigurationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&unifiv1.Networkconfiguration{}).
		Named("networkconfiguration").
		Complete(r)
}
