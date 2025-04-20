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

// FirewallRuleReconciler reconciles a FirewallRule object
type FirewallRuleReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	UnifiClient  *unifi.UnifiClient
	ConfigLoader *config.ConfigLoaderType
}

const firewallRuleFinalizer = "finalizer.unifi.engen.priv.no/firewallrule"

// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallrules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallrules/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=list;get;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=list;get;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the FirewallRule object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile

func fillDefaultRule() goUnifi.FirewallPolicy {
	var firewallRule goUnifi.FirewallPolicy
	firewallRule.Action = "ALLOW"
	firewallRule.CreateAllowRespond = true
	firewallRule.ConnectionStateType = "ALL"
	firewallRule.ConnectionStates = []string{}
	firewallRule.Destination = goUnifi.FirewallDestination{
		MatchOppositePorts: false,
		MatchingTarget:     "IP",
		MatchingTargetType: "OBJECT",
	}
	firewallRule.Enabled = true
	firewallRule.ICMPTypename = "ANY"
	firewallRule.ICMPV6Typename = "ANY"
	firewallRule.MatchIPSec = false
	firewallRule.MatchOppositeProtocol = false
	firewallRule.Predefined = false
	firewallRule.Schedule = goUnifi.FirewallSchedule{
		Mode:         "ALWAYS",
		RepeatOnDays: []string{},
		TimeAllDay:   false,
	}
	firewallRule.Source = goUnifi.FirewallSource{
		MatchMac:              false,
		MatchOppositePorts:    false,
		MatchOppositeNetworks: false,
	}

	return firewallRule
}

func (r *FirewallRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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

	var firewallRule unifiv1beta1.FirewallRule

	if err := r.Get(ctx, req.NamespacedName, &firewallRule); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Info(firewallRule.Spec.Name)

	if firewallRule.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(&firewallRule, firewallRuleFinalizer) {
			err := r.UnifiClient.Reauthenticate()
			if err != nil {
				return ctrl.Result{}, err
			}
			log.Info("Running finalizer logic for FirewallRule", "name", firewallRule.Name)

			if len(firewallRule.Status.ResourcesManaged.UnifiFirewallRules) > 0 {
				for i, UnifiFirewallRule := range firewallRule.Status.ResourcesManaged.UnifiFirewallRules {
					if len(UnifiFirewallRule.TcpIpv4ID) > 0 {
						err := r.UnifiClient.Client.DeleteFirewallPolicy(context.Background(), r.UnifiClient.SiteID, UnifiFirewallRule.TcpIpv4ID)
						if err != nil {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						} else {
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].TcpIpv4ID = ""
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
							}
						}
					}
					if len(UnifiFirewallRule.UdpIpv4ID) > 0 {
						err := r.UnifiClient.Client.DeleteFirewallPolicy(context.Background(), r.UnifiClient.SiteID, UnifiFirewallRule.UdpIpv4ID)
						if err != nil {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						} else {
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].UdpIpv4ID = ""
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
							}
						}
					}
					if len(UnifiFirewallRule.TcpIpv6ID) > 0 {
						err := r.UnifiClient.Client.DeleteFirewallPolicy(context.Background(), r.UnifiClient.SiteID, UnifiFirewallRule.TcpIpv6ID)
						if err != nil {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						} else {
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].TcpIpv6ID = ""
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
							}
						}
					}
					if len(UnifiFirewallRule.UdpIpv6ID) > 0 {
						err := r.UnifiClient.Client.DeleteFirewallPolicy(context.Background(), r.UnifiClient.SiteID, UnifiFirewallRule.UdpIpv6ID)
						if err != nil {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						} else {
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].UdpIpv6ID = ""
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
							}
						}
					}
				}
			}

			if len(firewallRule.Status.ResourcesManaged.FirewallGroups) > 0 {
				for i, firewallGroup := range firewallRule.Status.ResourcesManaged.FirewallGroups {
					var firewallGroupCRD unifiv1beta1.FirewallGroup
					if firewallGroup.Name != "" {
						if err := r.Get(ctx, types.NamespacedName{Name: firewallGroup.Name, Namespace: firewallGroupCRD.Namespace}, &firewallGroupCRD); err != nil {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						}
						if err := r.Delete(ctx, &firewallGroupCRD); err != nil {
							log.Error(err, "Could not delete firewall group")
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						}
						firewallRule.Status.ResourcesManaged.FirewallGroups[i].Name = ""
						firewallRule.Status.ResourcesManaged.FirewallGroups[i].Namespace = ""
						if err := r.Status().Update(ctx, &firewallRule); err != nil {
							return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
						}
					}
				}
			}
			controllerutil.RemoveFinalizer(&firewallRule, firewallRuleFinalizer)
			if err := r.Update(ctx, &firewallRule); err != nil {
				return ctrl.Result{}, err
			}

			log.Info("Successfully finalized FirewallGroup")
		}
		return ctrl.Result{}, nil
	}
	if !controllerutil.ContainsFinalizer(&firewallRule, firewallRuleFinalizer) {
		controllerutil.AddFinalizer(&firewallRule, firewallRuleFinalizer)
		if err := r.Update(ctx, &firewallRule); err != nil {
			return ctrl.Result{}, err
		}
	}

	firewallruleindex := make(map[string]int)

	nextIndex := 0
	if firewallRule.Status.ResourcesManaged == nil {
		firewallGroupsManaged := []unifiv1beta1.FirewallGroupEntry{}
		unifiFirewallRules := []unifiv1beta1.UnifiFirewallRuleEntry{}
		firewallRule.Status.ResourcesManaged = &unifiv1beta1.FirewallRuleResourcesManaged{
			UnifiFirewallRules: unifiFirewallRules,
			FirewallGroups:     firewallGroupsManaged,
		}
	} else {
		for index, firewallRuleEntry := range firewallRule.Status.ResourcesManaged.UnifiFirewallRules {
			firewallruleindex[firewallRuleEntry.From+"/"+firewallRuleEntry.To] = index
			nextIndex = nextIndex + 1
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

	for _, dest_group := range firewallRule.Spec.Destination.FirewallGroups {
		namespace := defaultNs
		if len(dest_group.Namespace) > 0 {
			namespace = dest_group.Namespace
		}
		destination_groups[namespace+"/"+dest_group.Name] = struct{}{}
	}
	for _, dest_service := range firewallRule.Spec.Destination.Services {
		namespace := defaultNs
		if len(dest_service.Namespace) > 0 {
			namespace = dest_service.Namespace
		}
		destination_services[namespace+"/"+dest_service.Name] = struct{}{}
	}
	log.Info(fmt.Sprintf("%+v", destination_services))
	var firewallGroupCRDs unifiv1beta1.FirewallGroupList
	var myFirewallGroups []unifiv1beta1.FirewallGroup
	if err = r.List(ctx, &firewallGroupCRDs); err != nil {
		log.Error(err, "Failed to list firewall groups")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}

	for _, firewallGroup := range firewallGroupCRDs.Items {
		if val, found := firewallGroup.Annotations["unifi.engen.priv.no/firewall-rule"]; found && val == firewallRule.Name {
			myFirewallGroups = append(myFirewallGroups, firewallGroup)
		} else if _, found := destination_groups[firewallGroup.Namespace+"/"+firewallGroup.Name]; found {
			myFirewallGroups = append(myFirewallGroups, firewallGroup)
		}
	}
	myFirewallGroupNames := make(map[string]struct{})
	for _, firewallGroup := range myFirewallGroups {
		myFirewallGroupNames[firewallGroup.Name] = struct{}{}
	}
	var serviceCRDs corev1.ServiceList
	var myServices []corev1.Service
	if err = r.List(ctx, &serviceCRDs); err != nil {
		log.Error(err, "Failed to list services")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}
	for _, service := range serviceCRDs.Items {
		skipService := false
		if val, found := service.Annotations["unifi.engen.priv.no/firewall-group"]; found {
			if _, found := myFirewallGroupNames[val]; found {
				skipService = true
			}
		}
		if val, found := service.Annotations["unifi.engen.priv.no/firewall-rule"]; found && val == firewallRule.Name && !skipService {
			myServices = append(myServices, service)
		} else if _, found := destination_services[service.Namespace+"/"+service.Name]; found && !skipService {
			myServices = append(myServices, service)
		}
	}

	for _, service := range myServices {
		log.Info(fmt.Sprintf("Should handle service %s", service.Name))
		var firewallGroupCRD unifiv1beta1.FirewallGroup
		if err := r.Get(ctx, types.NamespacedName{
			Name:      toKubeName("k8s-auto" + "_" + service.Namespace + "/" + service.Name),
			Namespace: firewallRule.Namespace,
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
					Namespace: firewallRule.Namespace,
				},
				Spec: unifiv1beta1.FirewallGroupSpec{
					Name: "auto-" + service.Namespace + "/" + service.Name,
					AutoCreatedFrom: unifiv1beta1.FirewallRuleEntry{
						Name:      firewallRule.Name,
						Namespace: firewallRule.Namespace,
					},
					ManualServices:               manualServices,
					MatchServicesInAllNamespaces: true,
				},
			}
			log.Info(fmt.Sprintf("%+v", createdFirewallGroupCRD))
			if err := r.Create(ctx, createdFirewallGroupCRD); err != nil {
				log.Error(err, fmt.Sprintf("Failed to create %s", createdFirewallGroupCRD.Name))
				return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
			} else {
				time.Sleep(10 * time.Second)
				_ = r.Get(ctx, types.NamespacedName{Name: createdFirewallGroupCRD.Name, Namespace: createdFirewallGroupCRD.Namespace}, &firewallGroupCRD)
			}
			log.Info(fmt.Sprintf("Adding %+v", firewallGroupCRD))
			myFirewallGroups = append(myFirewallGroups, firewallGroupCRD)
			found := false
			for _, managedFirewallGroup := range firewallRule.Status.ResourcesManaged.FirewallGroups {
				if managedFirewallGroup.Name == firewallGroupCRD.Name && managedFirewallGroup.Namespace == firewallGroupCRD.Namespace {
					found = true
				}
			}
			if !found {
				firewallRule.Status.ResourcesManaged.FirewallGroups = append(firewallRule.Status.ResourcesManaged.FirewallGroups, unifiv1beta1.FirewallGroupEntry{Name: firewallGroupCRD.Name, Namespace: firewallGroupCRD.Namespace})
				if err := r.Status().Update(ctx, &firewallRule); err != nil {
					log.Error(err, "Failed to update status with added firewallgroup")
				}
			}

		}
	}
	unifi_firewall_rules, err := r.UnifiClient.Client.ListFirewallPolicy(context.Background(), r.UnifiClient.SiteID)
	if err != nil {
		log.Error(err, "Could not list firewall rules")
		return ctrl.Result{}, err
	}
	unifiFirewallruleNames := make(map[string]struct{})
	for _, unifi_firewall_rule := range unifi_firewall_rules {
		unifiFirewallruleNames[unifi_firewall_rule.Name] = struct{}{}
	}
	log.Info(fmt.Sprintf("Number of firewall rules: %d", len(unifi_firewall_rules)))

	for _, zoneEntry := range firewallRule.Spec.Source.FirewallZones {
		namespace := defaultNs
		if len(zoneEntry.Namespace) > 0 {
			namespace = zoneEntry.Namespace
		}
		if i, found := zoneCRDNames[namespace+"/"+zoneEntry.Name]; found {
			log.Info(fmt.Sprintf("Creating firewallrules for %s", zoneCRDs.Items[i].Name))
			for _, firewallGroup := range myFirewallGroups {
				i, found := firewallruleindex["zone:"+zoneCRDs.Items[i].Name+"/"+firewallGroup.Name]
				if !found {
					firewallRuleEntry := unifiv1beta1.UnifiFirewallRuleEntry{
						From:      "zone:" + zoneCRDs.Items[i].Name,
						To:        firewallGroup.Name,
						TcpIpv4ID: "",
						UdpIpv4ID: "",
						TcpIpv6ID: "",
						UdpIpv6ID: "",
					}
					firewallRule.Status.ResourcesManaged.UnifiFirewallRules = append(firewallRule.Status.ResourcesManaged.UnifiFirewallRules, firewallRuleEntry)
					i = nextIndex
					nextIndex = nextIndex + 1
				}

				if len(firewallGroup.Status.ResolvedIPV4Addresses) > 0 {
					if len(firewallGroup.Status.ResolvedTCPPorts) > 0 {
						rulename := "k8s-fw-" + firewallRule.Name + "-" + zoneCRDs.Items[i].Name + "-" + firewallGroup.Name + "-ipv4-tcp"
						if _, found := unifiFirewallruleNames[rulename]; !found {
							log.Info(fmt.Sprintf("Creating ipv4 tcp firewallrule for %s to %s: %s", zoneCRDs.Items[i].Name, firewallGroup.Name, rulename))
							unifiFirewallRule := fillDefaultRule()
							unifiFirewallRule.Name = rulename
							unifiFirewallRule.Source.PortMatchingType = "ANY"
							unifiFirewallRule.Source.ZoneID = zoneCRDs.Items[i].Spec.ID
							unifiFirewallRule.Source.MatchingTarget = "ANY"
							unifiFirewallRule.Protocol = "tcp"
							unifiFirewallRule.IPVersion = "IPV4"
							unifiFirewallRule.Description = fmt.Sprintf("Allow tcp IPV4 from %s to %s", zoneCRDs.Items[i].Name, firewallGroup.Name)
							unifiFirewallRule.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallRule.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV4Object.ID
							unifiFirewallRule.Destination.MatchingTarget = "IP"
							unifiFirewallRule.Destination.PortMatchingType = "OBJECT"
							unifiFirewallRule.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.TCPPortsObject.ID
							unifiFirewallRule.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall rule from zone  %s to %s: %+v", zoneCRDs.Items[i].Name, firewallGroup.Name, unifiFirewallRule))
							pretty, _ := json.MarshalIndent(unifiFirewallRule, "", "  ")
							log.Info(string(pretty))
							updatedRule, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallRule)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].TcpIpv4ID = updatedRule.ID
							if err = r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{}, err
							}
						} else {
							log.Info(fmt.Sprintf("Firewall rule for ipv4 tcp %s to %s already exists", zoneCRDs.Items[i].Name, firewallGroup.Name))
						}
					}
					if len(firewallGroup.Status.ResolvedUDPPorts) > 0 {
						rulename := "k8s-fw-" + firewallRule.Name + "-" + zoneCRDs.Items[i].Name + "-" + firewallGroup.Name + "-ipv4-udp"
						if _, found := unifiFirewallruleNames[rulename]; !found {
							log.Info(fmt.Sprintf("Creating ipv4 udp firewallrule for %s to %s: %s", zoneCRDs.Items[i].Name, firewallGroup.Name, rulename))
							unifiFirewallRule := fillDefaultRule()
							unifiFirewallRule.Name = rulename
							unifiFirewallRule.Source.PortMatchingType = "ANY"
							unifiFirewallRule.Source.ZoneID = zoneCRDs.Items[i].Spec.ID
							unifiFirewallRule.Source.MatchingTarget = "ANY"
							unifiFirewallRule.Protocol = "udp"
							unifiFirewallRule.IPVersion = "IPV4"
							unifiFirewallRule.Description = fmt.Sprintf("Allow udp IPV4 from %s to %s", zoneCRDs.Items[i].Name, firewallGroup.Name)
							unifiFirewallRule.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallRule.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV4Object.ID
							unifiFirewallRule.Destination.MatchingTarget = "IP"
							unifiFirewallRule.Destination.PortMatchingType = "OBJECT"
							unifiFirewallRule.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.UDPPortsObject.ID
							unifiFirewallRule.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall rule from zone  %s to %s: %+v", zoneCRDs.Items[i].Name, firewallGroup.Name, unifiFirewallRule))
							pretty, _ := json.MarshalIndent(unifiFirewallRule, "", "  ")
							log.Info(string(pretty))
							updatedRule, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallRule)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].UdpIpv4ID = updatedRule.ID
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall rule for ipv4 udp %s to %s already exists", zoneCRDs.Items[i].Name, firewallGroup.Name))
						}
					}
				}
				if len(firewallGroup.Status.ResolvedIPV6Addresses) > 0 {
					if len(firewallGroup.Status.ResolvedTCPPorts) > 0 {
						rulename := "k8s-fw-" + firewallRule.Name + "-" + zoneCRDs.Items[i].Name + "-" + firewallGroup.Name + "-ipv6-tcp"
						if _, found := unifiFirewallruleNames[rulename]; !found {
							log.Info(fmt.Sprintf("Creating ipv6 tcp firewallrule for %s to %s: %s", zoneCRDs.Items[i].Name, firewallGroup.Name, rulename))
							unifiFirewallRule := fillDefaultRule()
							unifiFirewallRule.Name = rulename
							unifiFirewallRule.Source.PortMatchingType = "ANY"
							unifiFirewallRule.Source.ZoneID = zoneCRDs.Items[i].Spec.ID
							unifiFirewallRule.Source.MatchingTarget = "ANY"
							unifiFirewallRule.Protocol = "tcp"
							unifiFirewallRule.IPVersion = "IPV6"
							unifiFirewallRule.Description = fmt.Sprintf("Allow tcp IPV6 from %s to %s", zoneCRDs.Items[i].Name, firewallGroup.Name)
							unifiFirewallRule.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallRule.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV6Object.ID
							unifiFirewallRule.Destination.MatchingTarget = "IP"
							unifiFirewallRule.Destination.PortMatchingType = "OBJECT"
							unifiFirewallRule.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.TCPPortsObject.ID
							unifiFirewallRule.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall rule from zone  %s to %s: %+v", zoneCRDs.Items[i].Name, firewallGroup.Name, unifiFirewallRule))
							pretty, _ := json.MarshalIndent(unifiFirewallRule, "", "  ")
							log.Info(string(pretty))
							updatedRule, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallRule)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].TcpIpv6ID = updatedRule.ID
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall rule for ipv6 tcp %s to %s already exists", zoneCRDs.Items[i].Name, firewallGroup.Name))
						}
					}
					if len(firewallGroup.Status.ResolvedUDPPorts) > 0 {
						rulename := "k8s-fw-" + firewallRule.Name + "-" + zoneCRDs.Items[i].Name + "-" + firewallGroup.Name + "-ipv6-udp"
						if _, found := unifiFirewallruleNames[rulename]; !found {
							log.Info(fmt.Sprintf("Creating ipv6 udp firewallrule for %s to %s: %s", zoneCRDs.Items[i].Name, firewallGroup.Name, rulename))
							unifiFirewallRule := fillDefaultRule()
							unifiFirewallRule.Name = rulename
							unifiFirewallRule.Source.PortMatchingType = "ANY"
							unifiFirewallRule.Source.ZoneID = zoneCRDs.Items[i].Spec.ID
							unifiFirewallRule.Source.MatchingTarget = "ANY"
							unifiFirewallRule.Protocol = "udp"
							unifiFirewallRule.IPVersion = "IPV6"
							unifiFirewallRule.Description = fmt.Sprintf("Allow udp IPV6 from %s to %s", zoneCRDs.Items[i].Name, firewallGroup.Name)
							unifiFirewallRule.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallRule.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV6Object.ID
							unifiFirewallRule.Destination.MatchingTarget = "IP"
							unifiFirewallRule.Destination.PortMatchingType = "OBJECT"
							unifiFirewallRule.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.UDPPortsObject.ID
							unifiFirewallRule.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall rule from zone  %s to %s: %+v", zoneCRDs.Items[i].Name, firewallGroup.Name, unifiFirewallRule))
							pretty, _ := json.MarshalIndent(unifiFirewallRule, "", "  ")
							log.Info(string(pretty))
							updatedRule, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallRule)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].UdpIpv6ID = updatedRule.ID
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall rule for ipv6 udp %s to %s already exists", zoneCRDs.Items[i].Name, firewallGroup.Name))
						}
					}
				}
			}
		}
	}
	for _, networkEntry := range firewallRule.Spec.Source.Networks {
		namespace := defaultNs
		if len(networkEntry.Namespace) > 0 {
			namespace = networkEntry.Namespace
		}
		if i, found := networkCRDNames[namespace+"/"+networkEntry.Name]; found {
			log.Info(fmt.Sprintf("Creating firewallrules for %s", networkCRDs.Items[i].Name))
			for _, firewallGroup := range myFirewallGroups {
				i, found := firewallruleindex["network:"+networkCRDs.Items[i].Name+"/"+firewallGroup.Name]
				if !found {
					firewallRuleEntry := unifiv1beta1.UnifiFirewallRuleEntry{
						From:      "zone:" + networkCRDs.Items[i].Name,
						To:        firewallGroup.Name,
						TcpIpv4ID: "",
						UdpIpv4ID: "",
						TcpIpv6ID: "",
						UdpIpv6ID: "",
					}
					firewallRule.Status.ResourcesManaged.UnifiFirewallRules = append(firewallRule.Status.ResourcesManaged.UnifiFirewallRules, firewallRuleEntry)
					i = nextIndex
					nextIndex = nextIndex + 1
				}
				if len(firewallGroup.Status.ResolvedIPV4Addresses) > 0 {
					if len(firewallGroup.Status.ResolvedTCPPorts) > 0 {
						rulename := "k8s-fw-" + firewallRule.Name + "-" + networkCRDs.Items[i].Name + "-" + firewallGroup.Name + "-ipv4-tcp"
						if _, found := unifiFirewallruleNames[rulename]; !found {
							log.Info(fmt.Sprintf("Creating ipv4 tcp firewallrule for %s to %s: %s", networkCRDs.Items[i].Name, firewallGroup.Name, rulename))
							unifiFirewallRule := fillDefaultRule()
							unifiFirewallRule.Name = rulename
							unifiFirewallRule.Source.NetworkIDs = []string{networkCRDs.Items[i].Spec.ID}
							unifiFirewallRule.Source.PortMatchingType = "ANY"
							unifiFirewallRule.Source.ZoneID = networkCRDs.Items[i].Status.FirewallZoneID
							unifiFirewallRule.Source.MatchingTarget = "NETWORK"
							unifiFirewallRule.Protocol = "tcp"
							unifiFirewallRule.IPVersion = "IPV4"
							unifiFirewallRule.Description = fmt.Sprintf("Allow tcp IPV4 from %s to %s", networkCRDs.Items[i].Name, firewallGroup.Name)
							unifiFirewallRule.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallRule.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV4Object.ID
							unifiFirewallRule.Destination.MatchingTarget = "IP"
							unifiFirewallRule.Destination.PortMatchingType = "OBJECT"
							unifiFirewallRule.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.TCPPortsObject.ID
							unifiFirewallRule.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall rule from network  %s to %s: %+v", networkCRDs.Items[i].Name, firewallGroup.Name, unifiFirewallRule))
							pretty, _ := json.MarshalIndent(unifiFirewallRule, "", "  ")
							log.Info(string(pretty))
							updatedRule, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallRule)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}

							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].TcpIpv4ID = updatedRule.ID
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{}, err
							}
						} else {
							log.Info(fmt.Sprintf("Firewall rule for ipv4 tcp %s to %s already exists", networkCRDs.Items[i].Name, firewallGroup.Name))
						}
					}
					if len(firewallGroup.Status.ResolvedUDPPorts) > 0 {
						rulename := "k8s-fw-" + firewallRule.Name + "-" + networkCRDs.Items[i].Name + "-" + firewallGroup.Name + "-ipv4-udp"
						if _, found := unifiFirewallruleNames[rulename]; !found {
							log.Info(fmt.Sprintf("Creating ipv4 udp firewallrule for %s to %s: %s", networkCRDs.Items[i].Name, firewallGroup.Name, rulename))
							unifiFirewallRule := fillDefaultRule()
							unifiFirewallRule.Name = rulename
							unifiFirewallRule.Source.NetworkIDs = []string{networkCRDs.Items[i].Spec.ID}
							unifiFirewallRule.Source.PortMatchingType = "ANY"
							unifiFirewallRule.Source.ZoneID = networkCRDs.Items[i].Status.FirewallZoneID
							unifiFirewallRule.Source.MatchingTarget = "NETWORK"
							unifiFirewallRule.Protocol = "udp"
							unifiFirewallRule.IPVersion = "IPV4"
							unifiFirewallRule.Description = fmt.Sprintf("Allow udp IPV4 from %s to %s", networkCRDs.Items[i].Name, firewallGroup.Name)
							unifiFirewallRule.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallRule.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV4Object.ID
							unifiFirewallRule.Destination.MatchingTarget = "IP"
							unifiFirewallRule.Destination.PortMatchingType = "OBJECT"
							unifiFirewallRule.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.UDPPortsObject.ID
							unifiFirewallRule.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall rule from network  %s to %s: %+v", networkCRDs.Items[i].Name, firewallGroup.Name, unifiFirewallRule))
							pretty, _ := json.MarshalIndent(unifiFirewallRule, "", "  ")
							log.Info(string(pretty))
							updatedRule, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallRule)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].UdpIpv4ID = updatedRule.ID
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall rule for ipv4 udp %s to %s already exists", networkCRDs.Items[i].Name, firewallGroup.Name))
						}
					}
				}
				if len(firewallGroup.Status.ResolvedIPV6Addresses) > 0 {
					if len(firewallGroup.Status.ResolvedTCPPorts) > 0 {
						rulename := "k8s-fw-" + firewallRule.Name + "-" + networkCRDs.Items[i].Name + "-" + firewallGroup.Name + "-ipv6-tcp"
						if _, found := unifiFirewallruleNames[rulename]; !found {
							log.Info(fmt.Sprintf("Creating ipv6 tcp firewallrule for %s to %s: %s", networkCRDs.Items[i].Name, firewallGroup.Name, rulename))
							unifiFirewallRule := fillDefaultRule()
							unifiFirewallRule.Name = rulename
							unifiFirewallRule.Source.NetworkIDs = []string{networkCRDs.Items[i].Spec.ID}
							unifiFirewallRule.Source.PortMatchingType = "ANY"
							unifiFirewallRule.Source.ZoneID = networkCRDs.Items[i].Status.FirewallZoneID
							unifiFirewallRule.Source.MatchingTarget = "NETWORK"
							unifiFirewallRule.Protocol = "tcp"
							unifiFirewallRule.IPVersion = "IPV6"
							unifiFirewallRule.Description = fmt.Sprintf("Allow tcp IPV6 from %s to %s", networkCRDs.Items[i].Name, firewallGroup.Name)
							unifiFirewallRule.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallRule.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV6Object.ID
							unifiFirewallRule.Destination.MatchingTarget = "IP"
							unifiFirewallRule.Destination.PortMatchingType = "OBJECT"
							unifiFirewallRule.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.TCPPortsObject.ID
							unifiFirewallRule.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall rule from network  %s to %s: %+v", networkCRDs.Items[i].Name, firewallGroup.Name, unifiFirewallRule))
							pretty, _ := json.MarshalIndent(unifiFirewallRule, "", "  ")
							log.Info(string(pretty))
							updatedRule, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallRule)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].TcpIpv6ID = updatedRule.ID
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall rule for ipv6 tcp %s to %s already exists", networkCRDs.Items[i].Name, firewallGroup.Name))
						}
					}
					if len(firewallGroup.Status.ResolvedUDPPorts) > 0 {
						rulename := "k8s-fw-" + firewallRule.Name + "-" + networkCRDs.Items[i].Name + "-" + firewallGroup.Name + "-ipv6-udp"
						if _, found := unifiFirewallruleNames[rulename]; !found {
							log.Info(fmt.Sprintf("Creating ipv6 udp firewallrule for %s to %s: %s", networkCRDs.Items[i].Name, firewallGroup.Name, rulename))
							unifiFirewallRule := fillDefaultRule()
							unifiFirewallRule.Name = rulename
							unifiFirewallRule.Source.NetworkIDs = []string{networkCRDs.Items[i].Spec.ID}
							unifiFirewallRule.Source.PortMatchingType = "ANY"
							unifiFirewallRule.Source.ZoneID = networkCRDs.Items[i].Status.FirewallZoneID
							unifiFirewallRule.Source.MatchingTarget = "NETWORK"
							unifiFirewallRule.Protocol = "udp"
							unifiFirewallRule.IPVersion = "IPV6"
							unifiFirewallRule.Description = fmt.Sprintf("Allow udp IPV6 from %s to %s", networkCRDs.Items[i].Name, firewallGroup.Name)
							unifiFirewallRule.Destination.MatchingTargetType = "OBJECT"
							unifiFirewallRule.Destination.IPGroupID = firewallGroup.Status.ResourcesManaged.IPV6Object.ID
							unifiFirewallRule.Destination.MatchingTarget = "IP"
							unifiFirewallRule.Destination.PortMatchingType = "OBJECT"
							unifiFirewallRule.Destination.PortGroupID = firewallGroup.Status.ResourcesManaged.UDPPortsObject.ID
							unifiFirewallRule.Destination.ZoneID = kubernetesZoneID

							log.Info(fmt.Sprintf("Trying to create firewall rule from network  %s to %s: %+v", networkCRDs.Items[i].Name, firewallGroup.Name, unifiFirewallRule))
							pretty, _ := json.MarshalIndent(unifiFirewallRule, "", "  ")
							log.Info(string(pretty))
							updatedRule, err := r.UnifiClient.Client.CreateFirewallPolicy(context.Background(), r.UnifiClient.SiteID, &unifiFirewallRule)
							if err != nil {
								log.Error(err, "Could not create firewall policy")
								return ctrl.Result{}, err
							}
							firewallRule.Status.ResourcesManaged.UnifiFirewallRules[i].UdpIpv6ID = updatedRule.ID
							if err := r.Status().Update(ctx, &firewallRule); err != nil {
								return ctrl.Result{}, err
							}

						} else {
							log.Info(fmt.Sprintf("Firewall rule for ipv6 udp %s to %s already exists", networkCRDs.Items[i].Name, firewallGroup.Name))
						}
					}
				}
			}
		}
	}
	return ctrl.Result{}, nil
}

func (r *FirewallRuleReconciler) mapFirewallGroupToFirewallRules(ctx context.Context, obj client.Object) []ctrl.Request {
	var requests []ctrl.Request
	firewallGroup, ok := obj.(*unifiv1beta1.FirewallGroup)
	if !ok {
		return requests
	}

	var allFirewallRules unifiv1beta1.FirewallRuleList

	if err := r.List(ctx, &allFirewallRules); err != nil {
		return nil
	}

	for _, rule := range allFirewallRules.Items {
		if rule.Spec.MatchFirewallGroupsInAllNamespaces || rule.Namespace == firewallGroup.Namespace {
			annotationKey := "unifi.engen.priv.no/firewall-rule"
			annotationVal := rule.Name
			if val, ok := firewallGroup.Annotations[annotationKey]; ok && (annotationVal == "" || val == annotationVal) {
				requests = append(requests, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      rule.Name,
						Namespace: rule.Namespace,
					},
				})
			}
		}
	}

	return requests
}

func (r *FirewallRuleReconciler) mapServiceToFirewallRules(ctx context.Context, obj client.Object) []ctrl.Request {
	var requests []ctrl.Request
	service, ok := obj.(*corev1.Service)
	if !ok {
		return requests
	}

	var allFirewallRules unifiv1beta1.FirewallRuleList

	if err := r.List(ctx, &allFirewallRules); err != nil {
		return nil
	}

	for _, rule := range allFirewallRules.Items {
		if rule.Spec.MatchServicesInAllNamespaces || rule.Namespace == service.Namespace {
			annotationKey := "unifi.engen.priv.no/firewall-rule"
			annotationVal := rule.Name
			if val, ok := service.Annotations[annotationKey]; ok && (annotationVal == "" || val == annotationVal) {
				requests = append(requests, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      rule.Name,
						Namespace: rule.Namespace,
					},
				})
			}
		}
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&unifiv1beta1.FirewallRule{}).
		Named("firewallrule").
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(r.mapServiceToFirewallRules),
		).
		Watches(
			&unifiv1beta1.FirewallGroup{},
			handler.EnqueueRequestsFromMapFunc(r.mapFirewallGroupToFirewallRules),
		).
		Complete(r)
}
