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
	"strings"
	"regexp"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	unifiv1beta1 "github.com/vegardengen/unifi-network-operator/api/v1beta1"
	"github.com/vegardengen/unifi-network-operator/internal/unifi"
	"github.com/vegardengen/unifi-network-operator/internal/config"
)

// FirewallZoneReconciler reconciles a FirewallZone object
type FirewallZoneReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	UnifiClient *unifi.UnifiClient
	ConfigLoader *config.ConfigLoaderType
}

func toKubeName(input string) string {
    // Lowercase the input
    name := strings.ToLower(input)

    // Replace any non-alphanumeric characters with dashes
    re := regexp.MustCompile(`[^a-z0-9\-\.]+`)
    name = re.ReplaceAllString(name, "-")

    // Trim leading and trailing non-alphanumerics
    name = strings.Trim(name, "-.")

    // Ensure it's not empty and doesn't exceed 253 characters
    if len(name) == 0 {
        name = "default"
    } else if len(name) > 253 {
        name = name[:253]
    }

    return name
}


// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallzones,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallzones/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallzones/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=list;get;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the FirewallZone object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *FirewallZoneReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	cfg, err := r.ConfigLoader.GetConfig(ctx, "unifi-operator-config")
        if err != nil {
            return ctrl.Result{}, err
        }

        defaultNs := cfg.Data["defaultNamespace"]

	var fwzCRDs unifiv1beta1.FirewallZoneList
	_ = r.List(ctx, &fwzCRDs, client.InNamespace(defaultNs))

	firewall_zones, err := r.UnifiClient.Client.ListFirewallZones(context.Background(), r.UnifiClient.SiteID)
	if err != nil {
		log.Error(err, "Could not list firewall zones")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}
	log.Info(fmt.Sprintf("Number of resources: %d Number of zones in Unifi: %d", len(fwzCRDs.Items), len(firewall_zones)))

	firewallZoneNamesUnifi := make(map[string]struct{})
	for _, zone := range firewall_zones {
		firewallZoneNamesUnifi[zone.Name] = struct{}{}
	}

	// Step 2: Collect zones in fwzCRDs that are NOT in firewall_zones
	for _, zone := range fwzCRDs.Items {
		if _, found := firewallZoneNamesUnifi[zone.Spec.Name]; !found {
			err := r.Delete(ctx, &zone)
			if err != nil {
				return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
			}
		}
	}
	firewallZoneNamesCRDs := make(map[string]struct{})
	for _, zoneCRD := range fwzCRDs.Items {
		firewallZoneNamesCRDs[zoneCRD.Spec.Name] = struct{}{}
	}
	for _, unifizone := range firewall_zones {
		log.Info(fmt.Sprintf("%+v\n", unifizone))
		if _, found := firewallZoneNamesCRDs[unifizone.Name]; !found {
			zoneCRD := &unifiv1beta1.FirewallZone {
				ObjectMeta : ctrl.ObjectMeta {
				   Name: toKubeName(unifizone.Name),
			  	   Namespace: defaultNs,
			   	},
				Spec: unifiv1beta1.FirewallZoneSpec {
					Name : unifizone.Name,
					ID : unifizone.ID,
					DefaultZone: unifizone.DefaultZone,
					ZoneKey : unifizone.ZoneKey,
					NetworkIDs : unifizone.NetworkIDs,
				},
			}
			err := r.Create(ctx, zoneCRD)
			if err != nil {
				return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
			}
		} else {
                    for _, zoneCRD := range fwzCRDs.Items {
			    if zoneCRD.Spec.Name == unifizone.Name {
				    zoneCRD.Spec = unifiv1beta1.FirewallZoneSpec {
                                        Name : unifizone.Name,
                                        ID : unifizone.ID,
                                        DefaultZone: unifizone.DefaultZone,
                                        ZoneKey : unifizone.ZoneKey,
                                        NetworkIDs : unifizone.NetworkIDs,
                                    }
	                            err := r.Update(ctx, &zoneCRD)
                                    if err != nil {
                                          return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
                                    }
		             }
                   }
	        }    
	}

	return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallZoneReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&unifiv1beta1.FirewallZone{}).
		Named("firewallzone").
		Complete(r)
}
