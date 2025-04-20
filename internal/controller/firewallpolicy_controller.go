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
	// "strings"
	"encoding/json"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	goUnifi "github.com/vegardengen/go-unifi/unifi"
	unifiv1beta1 "github.com/vegardengen/unifi-network-operator/api/v1beta1"
	"github.com/vegardengen/unifi-network-operator/internal/config"
	"github.com/vegardengen/unifi-network-operator/internal/unifi"
)

// FirewallPolicyReconciler reconciles a FirewallPolicy object
type FirewallPolicyReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	UnifiClient  *unifi.UnifiClient
	ConfigLoader *config.ConfigLoaderType
}

const firewallPolicyFinalizer = "finalizer.unifi.engen.priv.no/firewallpolicy"

// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=list;get;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=list;get;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the FirewallPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile

func fillDefaultPolicy() goUnifi.FirewallPolicy {
	var firewallPolicy goUnifi.FirewallPolicy
	firewallPolicy.Action = "ALLOW"
	firewallPolicy.CreateAllowRespond = true
	firewallPolicy.ConnectionStateType = "ALL"
	firewallPolicy.ConnectionStates = []string{}
	firewallPolicy.Destination = goUnifi.FirewallDestination{
		MatchOppositePorts: false,
		MatchingTarget:     "IP",
		MatchingTargetType: "OBJECT",
	}
	firewallPolicy.Enabled = true
	firewallPolicy.ICMPTypename = "ANY"
	firewallPolicy.ICMPV6Typename = "ANY"
	firewallPolicy.MatchIPSec = false
	firewallPolicy.MatchOppositeProtocol = false
	firewallPolicy.Predefined = false
	firewallPolicy.Schedule = goUnifi.FirewallSchedule{
		Mode:         "ALWAYS",
		RepeatOnDays: []string{},
		TimeAllDay:   false,
	}
	firewallPolicy.Source = goUnifi.FirewallSource{
		MatchMac:              false,
		MatchOppositePorts:    false,
		MatchOppositeNetworks: false,
	}

	return firewallPolicy
}

func (r *FirewallPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// TODO(user): your logic here

	cfg, err := r.ConfigLoader.GetConfig(ctx, "unifi-operator-config")
	if err != nil {
		return ctrl.Result{}, err
	}

	defaultNs := cfg.Data["defaultNamespace"]
	kubernetesZone := cfg.Data["kubernetesUnifiZone"]
	var kubernetesZoneID string
	log.Info(defaultNs)
	log.Info(kubernetesZone)

	var firewallPolicy unifiv1beta1.FirewallPolicy

	if err := r.Get(ctx, req.NamespacedName, &firewallPolicy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Info(firewallPolicy.Spec.Name)

	if firewallPolicy.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(&firewallPolicy, firewallPolicyFinalizer) {
			err := r.UnifiClient.Reauthenticate()
			if err != nil {
				return ctrl.Result{}, err
			}
			log.Info("Running finalizer logic for FirewallPolicy", "name", firewallPolicy.Name)

			if len(firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies) > 0 {
				for i, UnifiFirewallPolicy := range firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies {
					log.Info(fmt.Sprintf("From: %s to: %s TcpIpv4: %s UdpIpv4: %s TcpIpv6: %s UdpIpv6: %s", UnifiFirewallPolicy.From, UnifiFirewallPolicy.To, UnifiFirewallPolicy.TcpIpv4ID, UnifiFirewallPolicy.UdpIpv4ID, UnifiFirewallPolicy.TcpIpv6ID, UnifiFirewallPolicy.UdpIpv6ID))
					if len(UnifiFirewallPolicy.TcpIpv4ID) > 0 {
						err := r.UnifiClient.Client.DeleteFirewallPolicy(context.Background(), r.UnifiClient.SiteID, UnifiFirewallPolicy.TcpIpv4ID)
						if err != nil && !strings.Contains(err.Error(), "not found") {
						} else {
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[i].TcpIpv4ID = ""
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
							}
						}
					}
					if len(UnifiFirewallPolicy.UdpIpv4ID) > 0 {
						err := r.UnifiClient.Client.DeleteFirewallPolicy(context.Background(), r.UnifiClient.SiteID, UnifiFirewallPolicy.UdpIpv4ID)
						if err != nil && !strings.Contains(err.Error(), "not found") {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						} else {
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[i].UdpIpv4ID = ""
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
							}
						}
					}
					if len(UnifiFirewallPolicy.TcpIpv6ID) > 0 {
						err := r.UnifiClient.Client.DeleteFirewallPolicy(context.Background(), r.UnifiClient.SiteID, UnifiFirewallPolicy.TcpIpv6ID)
						if err != nil && !strings.Contains(err.Error(), "not found") {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						} else {
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[i].TcpIpv6ID = ""
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
							}
						}
					}
					if len(UnifiFirewallPolicy.UdpIpv6ID) > 0 {
						err := r.UnifiClient.Client.DeleteFirewallPolicy(context.Background(), r.UnifiClient.SiteID, UnifiFirewallPolicy.UdpIpv6ID)
						if err != nil && !strings.Contains(err.Error(), "not found") {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						} else {
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[i].UdpIpv6ID = ""
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
							}
						}
					}
				}
			}

			if len(firewallPolicy.Status.ResourcesManaged.FirewallGroups) > 0 {
				for i, firewallGroup := range firewallPolicy.Status.ResourcesManaged.FirewallGroups {
					var firewallGroupCRD unifiv1beta1.FirewallGroup
					if firewallGroup.Name != "" {
						if err := r.Get(ctx, types.NamespacedName{Name: firewallGroup.Name, Namespace: firewallGroup.Namespace}, &firewallGroupCRD); err != nil {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						}
						if err := r.Delete(ctx, &firewallGroupCRD); err != nil {
							log.Error(err, "Could not delete firewall group")
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						}
						firewallPolicy.Status.ResourcesManaged.FirewallGroups[i].Name = ""
						firewallPolicy.Status.ResourcesManaged.FirewallGroups[i].Namespace = ""
						if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						}
					}
				}
			}
			controllerutil.RemoveFinalizer(&firewallPolicy, firewallPolicyFinalizer)
			if err := r.Update(ctx, &firewallPolicy); err != nil {
				return ctrl.Result{}, err
			}

			log.Info("Successfully finalized FirewallGroup")
		}
		return ctrl.Result{}, nil
	}
	if !controllerutil.ContainsFinalizer(&firewallPolicy, firewallPolicyFinalizer) {
		controllerutil.AddFinalizer(&firewallPolicy, firewallPolicyFinalizer)
		if err := r.Update(ctx, &firewallPolicy); err != nil {
			return ctrl.Result{}, err
		}
	}
	// Create an index of already managed firewall policy entries, with source and destination as the key and placement in status field array as value. If no managed firewall policy
	// entries, this is a new policy and we will create an empty index and set empty lists in the status field of the firewallPolicy resource.

	firewallpolicyindex := make(map[string]int)

	nextFirewallPolicyIndex := 0
	if firewallPolicy.Status.ResourcesManaged == nil {
		firewallGroupsManaged := []unifiv1beta1.FirewallGroupEntry{}
		unifiFirewallPolicies := []unifiv1beta1.UnifiFirewallPolicyEntry{}
		firewallPolicy.Status.ResourcesManaged = &unifiv1beta1.FirewallPolicyResourcesManaged{
			UnifiFirewallPolicies: unifiFirewallPolicies,
			FirewallGroups:        firewallGroupsManaged,
		}
	} else {
		for index, firewallPolicyEntry := range firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies {
			firewallpolicyindex[firewallPolicyEntry.From+"/"+firewallPolicyEntry.To] = index
			nextFirewallPolicyIndex = nextFirewallPolicyIndex + 1
		}
	}

	err = r.UnifiClient.Reauthenticate()
	if err != nil {
		return ctrl.Result{}, err
	}

	var zoneCRDs unifiv1beta1.FirewallZoneList
	var networkCRDs unifiv1beta1.NetworkconfigurationList

	err = r.List(ctx, &zoneCRDs)
	if err != nil {
		log.Error(err, "Could not list firewall zones")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}

	// Create an index of zones, with namespace/name as key and placement in zoneCRDs as value. This enables getting the zone properties from specified namespace/name in
	// the policy entries. If Namespace is not specified, default will be taken from the configmap.

	zoneCRDNames := make(map[string]int)

	for i, zoneCRD := range zoneCRDs.Items {
		namespace := defaultNs
		if len(zoneCRD.Namespace) > 0 {
			namespace = zoneCRD.Namespace
		}
		if kubernetesZone == zoneCRD.Name {
			kubernetesZoneID = zoneCRD.Spec.ID
			log.Info(fmt.Sprintf("Zone for kubernetes resources: %s with ID %s", kubernetesZone, kubernetesZoneID))
		}
		zoneCRDNames[namespace+"/"+zoneCRD.Name] = i
	}

	err = r.List(ctx, &networkCRDs)
	if err != nil {
		log.Error(err, "Could not list networks")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}

	// Create an index of networks, with namespace/name as key and placement in networkCRDs as value. This enables getting the network properties from specified namespace/name in
	// the policy entries.

	networkCRDNames := make(map[string]int)

	for i, networkCRD := range networkCRDs.Items {
		namespace := defaultNs
		if len(networkCRD.Namespace) > 0 {
			namespace = networkCRD.Namespace
		}
		networkCRDNames[namespace+"/"+networkCRD.Name] = i
	}

	destination_services := make(map[string]struct{})
	destination_groups := make(map[string]struct{})

	// Run through the list of specified firewall groups destinations and service desitnations and create an index with namespace/name as key.
	// This will be used when running through all firewall groups and servics known, to see if a rule should be added.

	for _, dest_group := range firewallPolicy.Spec.Destination.FirewallGroups {
		namespace := defaultNs
		if len(dest_group.Namespace) > 0 {
			namespace = dest_group.Namespace
		}
		destination_groups[namespace+"/"+dest_group.Name] = struct{}{}
	}
	for _, dest_service := range firewallPolicy.Spec.Destination.Services {
		namespace := defaultNs
		if len(dest_service.Namespace) > 0 {
			namespace = dest_service.Namespace
		}
		destination_services[namespace+"/"+dest_service.Name] = struct{}{}
	}

	var firewallGroupCRDs unifiv1beta1.FirewallGroupList
	var myFirewallGroups []unifiv1beta1.FirewallGroup

	if err = r.List(ctx, &firewallGroupCRDs); err != nil {
		log.Error(err, "Failed to list firewall groups")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}

	// Run through all firewall groups. Add them to the myFirewallGroups list if they either have an annotations or is specified in the resource.

	for _, firewallGroup := range firewallGroupCRDs.Items {
		if val, found := firewallGroup.Annotations["unifi.engen.priv.no/firewall-policy"]; found && ((strings.Contains(val, "/") && val == firewallPolicy.Namespace+"/"+firewallPolicy.Name) || (val == firewallPolicy.Name && firewallPolicy.Namespace == defaultNs)) {
			myFirewallGroups = append(myFirewallGroups, firewallGroup)
		} else if _, found := destination_groups[firewallGroup.Namespace+"/"+firewallGroup.Name]; found {
			myFirewallGroups = append(myFirewallGroups, firewallGroup)
		}
	}

	// Create an index with namespace/name as value,

	myFirewallGroupNames := make(map[string]struct{})
	for _, firewallGroup := range myFirewallGroups {
		myFirewallGroupNames[firewallGroup.Namespace+"/"+firewallGroup.Name] = struct{}{}
	}

	var serviceCRDs corev1.ServiceList
	var myServices []corev1.Service
	if err = r.List(ctx, &serviceCRDs); err != nil {
		log.Error(err, "Failed to list services")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}

	// Run through all services. Check if they are part of the manually specified services or have an annotation, and add it to the myServices list if found
	for _, service := range serviceCRDs.Items {
		skipService := false
		if val, found := service.Annotations["unifi.engen.priv.no/firewall-group"]; found {
			if _, found := myFirewallGroupNames[val]; found {

				skipService = true
			}
		}
		if val, found := service.Annotations["unifi.engen.priv.no/firewall-policy"]; found && ((strings.Contains(val, "/") && val == firewallPolicy.Namespace+"/"+firewallPolicy.Name) || (val == firewallPolicy.Name && firewallPolicy.Namespace == defaultNs)) && !skipService {
			myServices = append(myServices, service)
		} else if _, found := destination_services[service.Namespace+"/"+service.Name]; found && !skipService {
			myServices = append(myServices, service)
		}
	}

	// Run through all services we should manage. Create a firewallgroup object for it, if it's not already created.
	// Add it to the list of managed unifiresources if it's created. Make sure to not add it twice.

	for _, service := range myServices {
		log.Info(fmt.Sprintf("Should handle service %s", service.Name))
		var firewallGroupCRD unifiv1beta1.FirewallGroup

		// Check if firewallgroup already exists. Add it to myFirewallGroups if it exists, create it if not.

		if err := r.Get(ctx, types.NamespacedName{
			Name:      toKubeName("k8s-auto" + "_" + service.Namespace + "/" + service.Name),
			Namespace: firewallPolicy.Namespace,
		}, &firewallGroupCRD); err == nil {
			myFirewallGroups = append(myFirewallGroups, firewallGroupCRD)
		} else {
			log.Info("Going to create firewall group")
			var manualServices []unifiv1beta1.ServiceEntry
			manualServices = append(manualServices, unifiv1beta1.ServiceEntry{
				Name:      service.Name,
				Namespace: service.Namespace,
			})
			createdFirewallGroupCRD := &unifiv1beta1.FirewallGroup{
				ObjectMeta: ctrl.ObjectMeta{
					Name:      toKubeName("k8s-auto" + "_" + service.Namespace + "/" + service.Name),
					Namespace: firewallPolicy.Namespace,
				},
				Spec: unifiv1beta1.FirewallGroupSpec{
					Name: "auto-" + service.Namespace + "/" + service.Name,
					AutoCreatedFrom: unifiv1beta1.FirewallPolicyEntry{
						Name:      firewallPolicy.Name,
						Namespace: firewallPolicy.Namespace,
					},
					ManualServices:               manualServices,
					MatchServicesInAllNamespaces: true,
				},
			}
			if err := r.Create(ctx, createdFirewallGroupCRD); err != nil {
				log.Error(err, fmt.Sprintf("Failed to create %s", createdFirewallGroupCRD.Name))
				return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
			} else {
				// Give it time to be fully created. It doesn't need to be handled and expanded at this point, but it should be before using it later.
				time.Sleep(10 * time.Second)
				_ = r.Get(ctx, types.NamespacedName{Name: createdFirewallGroupCRD.Name, Namespace: createdFirewallGroupCRD.Namespace}, &firewallGroupCRD)
			}
			log.Info(fmt.Sprintf("Adding %+v", firewallGroupCRD))
			myFirewallGroups = append(myFirewallGroups, firewallGroupCRD)

			// Run through list of already managed Unifi firewallgroups to check if it's already on the list, to  avoid having it in list twice.

			found := false
			for _, managedFirewallGroup := range firewallPolicy.Status.ResourcesManaged.FirewallGroups {
				if managedFirewallGroup.Name == firewallGroupCRD.Name && managedFirewallGroup.Namespace == firewallGroupCRD.Namespace {
					found = true
				}
			}

			// Add it to resource status field.
			if !found {
				firewallPolicy.Status.ResourcesManaged.FirewallGroups = append(firewallPolicy.Status.ResourcesManaged.FirewallGroups, unifiv1beta1.FirewallGroupEntry{Name: firewallGroupCRD.Name, Namespace: firewallGroupCRD.Namespace})
				if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
					log.Error(err, "Failed to update status with added firewallgroup")
				}
			}

		}
	}

	// Finished listing destinations. Starting to handle source specifications.
	// Source can be either zones or networks managed by/known to the operator. Specified by namespace and name. Use default from configmap if namespace is not specified.

	unifi_firewall_policies, err := r.UnifiClient.Client.ListFirewallPolicy(context.Background(), r.UnifiClient.SiteID)
	if err != nil {
		log.Error(err, "Could not list firewall policies")
		return ctrl.Result{}, err
	}

	// Create an index of Unifi firewall policy names.
	unifiFirewallpolicyNames := make(map[string]struct{})
	for _, unifi_firewall_policy := range unifi_firewall_policies {
		unifiFirewallpolicyNames[unifi_firewall_policy.Name] = struct{}{}
	}
	log.Info(fmt.Sprintf("Number of firewall policies: %d", len(unifi_firewall_policies)))

	// Run through specified source zones and check if we should handle them.
	for _, zoneEntry := range firewallPolicy.Spec.Source.FirewallZones {
		namespace := defaultNs
		if len(zoneEntry.Namespace) > 0 {
			namespace = zoneEntry.Namespace
		}

		if zoneIndex, found := zoneCRDNames[namespace+"/"+zoneEntry.Name]; found {
			// Should handle, so we create firewall policies.

			log.Info(fmt.Sprintf("Creating firewallpolicies for %s", zoneCRDs.Items[zoneIndex].Name))

			// Run through destination firewall groups and enumerate and create polices if they don't already exist.

			for _, firewallGroup := range myFirewallGroups {
				found := false

				index, found := firewallpolicyindex["zone:"+zoneCRDs.Items[zoneIndex].Name+"/"+firewallGroup.Name]

				// Not found? We add an empty entry in status field.
				if !found {
					firewallPolicyEntry := unifiv1beta1.UnifiFirewallPolicyEntry{
						From:      "zone:" + zoneCRDs.Items[zoneIndex].Name,
						To:        firewallGroup.Name,
						TcpIpv4ID: "",
						UdpIpv4ID: "",
						TcpIpv6ID: "",
						UdpIpv6ID: "",
					}
					firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies = append(firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies, firewallPolicyEntry)
					index = nextFirewallPolicyIndex
					nextFirewallPolicyIndex = nextFirewallPolicyIndex + 1
				}

				// Create policies for all permutations of Ipversion and protocol.

				if len(firewallGroup.Status.ResolvedIPV4Addresses) > 0 {
					if len(firewallGroup.Status.ResolvedTCPPorts) > 0 {
						policyname := "k8s-fw-" + firewallPolicy.Name + "-" + "zone:" + zoneCRDs.Items[zoneIndex].Name + "-" + firewallGroup.Name + "-ipv4-tcp"
						if _, found := unifiFirewallpolicyNames[policyname]; !found {
							log.Info(fmt.Sprintf("Creating ipv4 tcp firewallpolicy for %s to %s: %s", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name, policyname))
							unifiFirewallPolicy := fillDefaultPolicy()
							unifiFirewallPolicy.Name = policyname
							unifiFirewallPolicy.Source.PortMatchingType = "ANY"
							unifiFirewallPolicy.Source.ZoneID = zoneCRDs.Items[zoneIndex].Spec.ID
							unifiFirewallPolicy.Source.MatchingTarget = "ANY"
							unifiFirewallPolicy.Protocol = "tcp"
							unifiFirewallPolicy.IPVersion = "IPV4"
							unifiFirewallPolicy.Description = fmt.Sprintf("Allow tcp IPV4 from %s to %s", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name)
							unifiFirewallPolicy.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallPolicy.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV4Object.ID
							unifiFirewallPolicy.Destination.MatchingTarget = "IP"
							unifiFirewallPolicy.Destination.PortMatchingType = "OBJECT"
							unifiFirewallPolicy.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.TCPPortsObject.ID
							unifiFirewallPolicy.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall policy from zone  %s to %s: %+v", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name, unifiFirewallPolicy))
							pretty, _ := json.MarshalIndent(unifiFirewallPolicy, "", "  ")
							log.Info(string(pretty))
							updatedPolicy, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallPolicy)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[index].TcpIpv4ID = updatedPolicy.ID
							if err = r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{}, err
							}
						} else {
							log.Info(fmt.Sprintf("Firewall policy for ipv4 tcp %s to %s already exists", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name))
						}
					}
					if len(firewallGroup.Status.ResolvedUDPPorts) > 0 {
						policyname := "k8s-fw-" + firewallPolicy.Name + "-" + "zone:" + zoneCRDs.Items[zoneIndex].Name + "-" + firewallGroup.Name + "-ipv4-udp"
						if _, found := unifiFirewallpolicyNames[policyname]; !found {
							log.Info(fmt.Sprintf("Creating ipv4 udp firewallpolicy for %s to %s: %s", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name, policyname))
							unifiFirewallPolicy := fillDefaultPolicy()
							unifiFirewallPolicy.Name = policyname
							unifiFirewallPolicy.Source.PortMatchingType = "ANY"
							unifiFirewallPolicy.Source.ZoneID = zoneCRDs.Items[zoneIndex].Spec.ID
							unifiFirewallPolicy.Source.MatchingTarget = "ANY"
							unifiFirewallPolicy.Protocol = "udp"
							unifiFirewallPolicy.IPVersion = "IPV4"
							unifiFirewallPolicy.Description = fmt.Sprintf("Allow udp IPV4 from %s to %s", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name)
							unifiFirewallPolicy.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallPolicy.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV4Object.ID
							unifiFirewallPolicy.Destination.MatchingTarget = "IP"
							unifiFirewallPolicy.Destination.PortMatchingType = "OBJECT"
							unifiFirewallPolicy.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.UDPPortsObject.ID
							unifiFirewallPolicy.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall policy from zone  %s to %s: %+v", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name, unifiFirewallPolicy))
							pretty, _ := json.MarshalIndent(unifiFirewallPolicy, "", "  ")
							log.Info(string(pretty))
							updatedPolicy, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallPolicy)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[index].UdpIpv4ID = updatedPolicy.ID
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall policy for ipv4 udp %s to %s already exists", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name))
						}
					}
				}
				if len(firewallGroup.Status.ResolvedIPV6Addresses) > 0 {
					if len(firewallGroup.Status.ResolvedTCPPorts) > 0 {
						policyname := "k8s-fw-" + firewallPolicy.Name + "-" + "zone:"+zoneCRDs.Items[zoneIndex].Name + "-" + firewallGroup.Name + "-ipv6-tcp"
						if _, found := unifiFirewallpolicyNames[policyname]; !found {
							log.Info(fmt.Sprintf("Creating ipv6 tcp firewallpolicy for %s to %s: %s", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name, policyname))
							unifiFirewallPolicy := fillDefaultPolicy()
							unifiFirewallPolicy.Name = policyname
							unifiFirewallPolicy.Source.PortMatchingType = "ANY"
							unifiFirewallPolicy.Source.ZoneID = zoneCRDs.Items[zoneIndex].Spec.ID
							unifiFirewallPolicy.Source.MatchingTarget = "ANY"
							unifiFirewallPolicy.Protocol = "tcp"
							unifiFirewallPolicy.IPVersion = "IPV6"
							unifiFirewallPolicy.Description = fmt.Sprintf("Allow tcp IPV6 from %s to %s", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name)
							unifiFirewallPolicy.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallPolicy.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV6Object.ID
							unifiFirewallPolicy.Destination.MatchingTarget = "IP"
							unifiFirewallPolicy.Destination.PortMatchingType = "OBJECT"
							unifiFirewallPolicy.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.TCPPortsObject.ID
							unifiFirewallPolicy.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall policy from zone  %s to %s: %+v", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name, unifiFirewallPolicy))
							pretty, _ := json.MarshalIndent(unifiFirewallPolicy, "", "  ")
							log.Info(string(pretty))
							updatedPolicy, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallPolicy)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[index].TcpIpv6ID = updatedPolicy.ID
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall policy for ipv6 tcp %s to %s already exists", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name))
						}
					}
					if len(firewallGroup.Status.ResolvedUDPPorts) > 0 {
						policyname := "k8s-fw-" + firewallPolicy.Name + "-" + "zone:"+zoneCRDs.Items[zoneIndex].Name + "-" + firewallGroup.Name + "-ipv6-udp"
						if _, found := unifiFirewallpolicyNames[policyname]; !found {
							log.Info(fmt.Sprintf("Creating ipv6 udp firewallpolicy for %s to %s: %s", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name, policyname))
							unifiFirewallPolicy := fillDefaultPolicy()
							unifiFirewallPolicy.Name = policyname
							unifiFirewallPolicy.Source.PortMatchingType = "ANY"
							unifiFirewallPolicy.Source.ZoneID = zoneCRDs.Items[zoneIndex].Spec.ID
							unifiFirewallPolicy.Source.MatchingTarget = "ANY"
							unifiFirewallPolicy.Protocol = "udp"
							unifiFirewallPolicy.IPVersion = "IPV6"
							unifiFirewallPolicy.Description = fmt.Sprintf("Allow udp IPV6 from %s to %s", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name)
							unifiFirewallPolicy.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallPolicy.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV6Object.ID
							unifiFirewallPolicy.Destination.MatchingTarget = "IP"
							unifiFirewallPolicy.Destination.PortMatchingType = "OBJECT"
							unifiFirewallPolicy.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.UDPPortsObject.ID
							unifiFirewallPolicy.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall policy from zone  %s to %s: %+v", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name, unifiFirewallPolicy))
							pretty, _ := json.MarshalIndent(unifiFirewallPolicy, "", "  ")
							log.Info(string(pretty))
							updatedPolicy, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallPolicy)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[index].UdpIpv6ID = updatedPolicy.ID
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall policy for ipv6 udp %s to %s already exists", zoneCRDs.Items[zoneIndex].Name, firewallGroup.Name))
						}
					}
				}
			}
		}
	}
	for _, networkEntry := range firewallPolicy.Spec.Source.Networks {
		namespace := defaultNs
		if len(networkEntry.Namespace) > 0 {
			namespace = networkEntry.Namespace
		}
		if networkIndex, found := networkCRDNames[namespace+"/"+networkEntry.Name]; found {
			log.Info(fmt.Sprintf("Creating firewallpolicies for %s", networkCRDs.Items[networkIndex].Name))
			for _, firewallGroup := range myFirewallGroups {
				index, found := firewallpolicyindex["network:"+networkCRDs.Items[networkIndex].Name+"/"+firewallGroup.Name]
				if !found {
					firewallPolicyEntry := unifiv1beta1.UnifiFirewallPolicyEntry{
						From:      "zone:" + networkCRDs.Items[networkIndex].Name,
						To:        firewallGroup.Name,
						TcpIpv4ID: "",
						UdpIpv4ID: "",
						TcpIpv6ID: "",
						UdpIpv6ID: "",
					}
					firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies = append(firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies, firewallPolicyEntry)
					index = nextFirewallPolicyIndex
					nextFirewallPolicyIndex = nextFirewallPolicyIndex + 1
				}
				if len(firewallGroup.Status.ResolvedIPV4Addresses) > 0 {
					if len(firewallGroup.Status.ResolvedTCPPorts) > 0 {
						policyname := "k8s-fw-" + firewallPolicy.Name + "-" + "network:"+networkCRDs.Items[networkIndex].Name + "-" + firewallGroup.Name + "-ipv4-tcp"
						if _, found := unifiFirewallpolicyNames[policyname]; !found {
							log.Info(fmt.Sprintf("Creating ipv4 tcp firewallpolicy for %s to %s: %s", networkCRDs.Items[networkIndex].Name, firewallGroup.Name, policyname))
							unifiFirewallPolicy := fillDefaultPolicy()
							unifiFirewallPolicy.Name = policyname
							unifiFirewallPolicy.Source.NetworkIDs = []string{networkCRDs.Items[networkIndex].Spec.ID}
							unifiFirewallPolicy.Source.PortMatchingType = "ANY"
							unifiFirewallPolicy.Source.ZoneID = networkCRDs.Items[networkIndex].Status.FirewallZoneID
							unifiFirewallPolicy.Source.MatchingTarget = "NETWORK"
							unifiFirewallPolicy.Protocol = "tcp"
							unifiFirewallPolicy.IPVersion = "IPV4"
							unifiFirewallPolicy.Description = fmt.Sprintf("Allow tcp IPV4 from %s to %s", networkCRDs.Items[networkIndex].Name, firewallGroup.Name)
							unifiFirewallPolicy.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallPolicy.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV4Object.ID
							unifiFirewallPolicy.Destination.MatchingTarget = "IP"
							unifiFirewallPolicy.Destination.PortMatchingType = "OBJECT"
							unifiFirewallPolicy.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.TCPPortsObject.ID
							unifiFirewallPolicy.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall policy from network  %s to %s: %+v", networkCRDs.Items[networkIndex].Name, firewallGroup.Name, unifiFirewallPolicy))
							pretty, _ := json.MarshalIndent(unifiFirewallPolicy, "", "  ")
							log.Info(string(pretty))
							updatedPolicy, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallPolicy)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}

							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[index].TcpIpv4ID = updatedPolicy.ID
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{}, err
							}
						} else {
							log.Info(fmt.Sprintf("Firewall policy for ipv4 tcp %s to %s already exists", networkCRDs.Items[networkIndex].Name, firewallGroup.Name))
						}
					}
					if len(firewallGroup.Status.ResolvedUDPPorts) > 0 {
						policyname := "k8s-fw-" + firewallPolicy.Name + "-" + "network:"+networkCRDs.Items[networkIndex].Name + "-" + firewallGroup.Name + "-ipv4-udp"
						if _, found := unifiFirewallpolicyNames[policyname]; !found {
							log.Info(fmt.Sprintf("Creating ipv4 udp firewallpolicy for %s to %s: %s", networkCRDs.Items[networkIndex].Name, firewallGroup.Name, policyname))
							unifiFirewallPolicy := fillDefaultPolicy()
							unifiFirewallPolicy.Name = policyname
							unifiFirewallPolicy.Source.NetworkIDs = []string{networkCRDs.Items[networkIndex].Spec.ID}
							unifiFirewallPolicy.Source.PortMatchingType = "ANY"
							unifiFirewallPolicy.Source.ZoneID = networkCRDs.Items[networkIndex].Status.FirewallZoneID
							unifiFirewallPolicy.Source.MatchingTarget = "NETWORK"
							unifiFirewallPolicy.Protocol = "udp"
							unifiFirewallPolicy.IPVersion = "IPV4"
							unifiFirewallPolicy.Description = fmt.Sprintf("Allow udp IPV4 from %s to %s", networkCRDs.Items[networkIndex].Name, firewallGroup.Name)
							unifiFirewallPolicy.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallPolicy.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV4Object.ID
							unifiFirewallPolicy.Destination.MatchingTarget = "IP"
							unifiFirewallPolicy.Destination.PortMatchingType = "OBJECT"
							unifiFirewallPolicy.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.UDPPortsObject.ID
							unifiFirewallPolicy.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall policy from network  %s to %s: %+v", networkCRDs.Items[networkIndex].Name, firewallGroup.Name, unifiFirewallPolicy))
							pretty, _ := json.MarshalIndent(unifiFirewallPolicy, "", "  ")
							log.Info(string(pretty))
							updatedPolicy, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallPolicy)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[index].UdpIpv4ID = updatedPolicy.ID
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall policy for ipv4 udp %s to %s already exists", networkCRDs.Items[networkIndex].Name, firewallGroup.Name))
						}
					}
				}
				if len(firewallGroup.Status.ResolvedIPV6Addresses) > 0 {
					if len(firewallGroup.Status.ResolvedTCPPorts) > 0 {
						policyname := "k8s-fw-" + firewallPolicy.Name + "-" + "network:"+networkCRDs.Items[networkIndex].Name + "-" + firewallGroup.Name + "-ipv6-tcp"
						if _, found := unifiFirewallpolicyNames[policyname]; !found {
							log.Info(fmt.Sprintf("Creating ipv6 tcp firewallpolicy for %s to %s: %s", networkCRDs.Items[networkIndex].Name, firewallGroup.Name, policyname))
							unifiFirewallPolicy := fillDefaultPolicy()
							unifiFirewallPolicy.Name = policyname
							unifiFirewallPolicy.Source.NetworkIDs = []string{networkCRDs.Items[networkIndex].Spec.ID}
							unifiFirewallPolicy.Source.PortMatchingType = "ANY"
							unifiFirewallPolicy.Source.ZoneID = networkCRDs.Items[networkIndex].Status.FirewallZoneID
							unifiFirewallPolicy.Source.MatchingTarget = "NETWORK"
							unifiFirewallPolicy.Protocol = "tcp"
							unifiFirewallPolicy.IPVersion = "IPV6"
							unifiFirewallPolicy.Description = fmt.Sprintf("Allow tcp IPV6 from %s to %s", networkCRDs.Items[networkIndex].Name, firewallGroup.Name)
							unifiFirewallPolicy.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallPolicy.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV6Object.ID
							unifiFirewallPolicy.Destination.MatchingTarget = "IP"
							unifiFirewallPolicy.Destination.PortMatchingType = "OBJECT"
							unifiFirewallPolicy.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.TCPPortsObject.ID
							unifiFirewallPolicy.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall policy from network  %s to %s: %+v", networkCRDs.Items[networkIndex].Name, firewallGroup.Name, unifiFirewallPolicy))
							pretty, _ := json.MarshalIndent(unifiFirewallPolicy, "", "  ")
							log.Info(string(pretty))
							updatedPolicy, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallPolicy)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[index].TcpIpv6ID = updatedPolicy.ID
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall policy for ipv6 tcp %s to %s already exists", networkCRDs.Items[networkIndex].Name, firewallGroup.Name))
						}
					}
					if len(firewallGroup.Status.ResolvedUDPPorts) > 0 {
						policyname := "k8s-fw-" + firewallPolicy.Name + "-" + "network:"+networkCRDs.Items[networkIndex].Name + "-" + firewallGroup.Name + "-ipv6-udp"
						if _, found := unifiFirewallpolicyNames[policyname]; !found {
							log.Info(fmt.Sprintf("Creating ipv6 udp firewallpolicy for %s to %s: %s", networkCRDs.Items[networkIndex].Name, firewallGroup.Name, policyname))
							unifiFirewallPolicy := fillDefaultPolicy()
							unifiFirewallPolicy.Name = policyname
							unifiFirewallPolicy.Source.NetworkIDs = []string{networkCRDs.Items[networkIndex].Spec.ID}
							unifiFirewallPolicy.Source.PortMatchingType = "ANY"
							unifiFirewallPolicy.Source.ZoneID = networkCRDs.Items[networkIndex].Status.FirewallZoneID
							unifiFirewallPolicy.Source.MatchingTarget = "NETWORK"
							unifiFirewallPolicy.Protocol = "udp"
							unifiFirewallPolicy.IPVersion = "IPV6"
							unifiFirewallPolicy.Description = fmt.Sprintf("Allow udp IPV6 from %s to %s", networkCRDs.Items[networkIndex].Name, firewallGroup.Name)
							unifiFirewallPolicy.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallPolicy.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV6Object.ID
							unifiFirewallPolicy.Destination.MatchingTarget = "IP"
							unifiFirewallPolicy.Destination.PortMatchingType = "OBJECT"
							unifiFirewallPolicy.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.UDPPortsObject.ID
							unifiFirewallPolicy.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall policy from network  %s to %s: %+v", networkCRDs.Items[networkIndex].Name, firewallGroup.Name, unifiFirewallPolicy))
							pretty, _ := json.MarshalIndent(unifiFirewallPolicy, "", "  ")
							log.Info(string(pretty))
							updatedPolicy, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallPolicy)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallPolicy.Status.ResourcesManaged.UnifiFirewallPolicies[index].UdpIpv6ID = updatedPolicy.ID
							if err := r.Status().Update(ctx, &firewallPolicy); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall policy for ipv6 udp %s to %s already exists", networkCRDs.Items[networkIndex].Name, firewallGroup.Name))
						}
					}
				}
			}
		}
	}
	return ctrl.Result{}, nil
}

func (r *FirewallPolicyReconciler) mapFirewallGroupToFirewallPolicies(ctx context.Context, obj client.Object) []ctrl.Request {
	var requests []ctrl.Request
	firewallGroup, ok := obj.(*unifiv1beta1.FirewallGroup)
	if !ok {
		return requests
	}

	var allFirewallPolicies unifiv1beta1.FirewallPolicyList

	if err := r.List(ctx, &allFirewallPolicies); err != nil {
		return nil
	}

	for _, policy := range allFirewallPolicies.Items {
		if policy.Spec.MatchFirewallGroupsInAllNamespaces || policy.Namespace == firewallGroup.Namespace {
			annotationKey := "unifi.engen.priv.no/firewall-policy"
			annotationVal := policy.Name
			if val, ok := firewallGroup.Annotations[annotationKey]; ok && (annotationVal == "" || val == annotationVal) {
				requests = append(requests, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					},
				})
			}
		}
	}

	return requests
}

func (r *FirewallPolicyReconciler) mapServiceToFirewallPolicies(ctx context.Context, obj client.Object) []ctrl.Request {
	var requests []ctrl.Request
	service, ok := obj.(*corev1.Service)
	if !ok {
		return requests
	}

	var allFirewallPolicies unifiv1beta1.FirewallPolicyList

	if err := r.List(ctx, &allFirewallPolicies); err != nil {
		return nil
	}

	for _, policy := range allFirewallPolicies.Items {
		if policy.Spec.MatchServicesInAllNamespaces || policy.Namespace == service.Namespace {
			annotationKey := "unifi.engen.priv.no/firewall-policy"
			annotationVal := policy.Name
			if val, ok := service.Annotations[annotationKey]; ok && (annotationVal == "" || val == annotationVal) {
				requests = append(requests, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      policy.Name,
						Namespace: policy.Namespace,
					},
				})
			}
		}
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&unifiv1beta1.FirewallPolicy{}).
		Named("firewallpolicy").
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(r.mapServiceToFirewallPolicies),
		).
		Watches(
			&unifiv1beta1.FirewallGroup{},
			handler.EnqueueRequestsFromMapFunc(r.mapFirewallGroupToFirewallPolicies),
		).
		Complete(r)
}
