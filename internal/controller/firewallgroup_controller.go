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
	"net"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	//	"sigs.k8s.io/controller-runtime/pkg/source"

	goUnifi "github.com/vegardengen/go-unifi/unifi"
	unifiv1beta1 "github.com/vegardengen/unifi-network-operator/api/v1beta1"
	"github.com/vegardengen/unifi-network-operator/internal/config"
	"github.com/vegardengen/unifi-network-operator/internal/unifi"
)

// FirewallGroupReconciler reconciles a FirewallGroup object
type FirewallGroupReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	UnifiClient  *unifi.UnifiClient
	ConfigLoader *config.ConfigLoaderType
}

// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallgroups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallgroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallgroups/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=services,verbs=list;get;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=list;get;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the FirewallGroup object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile

func (r *FirewallGroupReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log := log.FromContext(ctx)

	cfg, err := r.ConfigLoader.GetConfig(ctx, "unifi-operator-config")
	if err != nil {
		return ctrl.Result{}, err
	}

	defaultNs := cfg.Data["defaultNamespace"]
	log.Info(defaultNs)

	var nwObj unifiv1beta1.FirewallGroup
	if err := r.Get(ctx, req.NamespacedName, &nwObj); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	log.Info(nwObj.Spec.Name)
	var ipv4, ipv6, tcpports, udpports []string

	for _, addressEntry := range nwObj.Spec.ManualAddresses {
		ip := net.ParseIP(addressEntry)

		if ip != nil {
			if ip.To4() != nil {
				log.Info(fmt.Sprintf("IPv4 address: %s", addressEntry))
				ipv4 = append(ipv4, addressEntry)
			} else {
				log.Info(fmt.Sprintf("IPv6 address: %s", addressEntry))
				ipv6 = append(ipv6, ip.String())
			}
		} else {
			addr, net, err := net.ParseCIDR(addressEntry)
			if err == nil && addr.Equal(net.IP) {
				if addr.To4() != nil {
					log.Info(fmt.Sprintf("Ipv4 Net: %s", net))
					ipv4 = append(ipv4, addressEntry)
				} else {
					mask, _ := net.Mask.Size()
					log.Info(fmt.Sprintf("Ipv6 Net: %s", net))
					ipv6 = append(ipv6, addr.Mask(net.Mask).String()+"/"+fmt.Sprint(mask))
				}
			} else {
				log.Error(err, fmt.Sprintf("Could not parse: %s", addressEntry))
				return reconcile.Result{}, err
			}
		}
	}

	for _, portEntry := range nwObj.Spec.ManualPorts {
		port_type := "tcp"
		port := portEntry
		if match, _ := regexp.MatchString("(?:tcp|udp)\\/?)\\d+", string(portEntry)); match {
			fields := strings.Split("/", portEntry)
			port_type = fields[0]
			port = fields[1]
		}
		if port_type == "tcp" {
			if !slices.Contains(tcpports, port) {
				tcpports = append(tcpports, port)
			}
		}
		if port_type == "udp" {
			if !slices.Contains(udpports, port) {
				tcpports = append(udpports, port)
			}
		}
	}
	var services corev1.ServiceList
	if nwObj.Spec.MatchServicesInAllNamespaces {
		if err := r.List(ctx, &services); err != nil {
			log.Error(err, "unable to list services")
			return reconcile.Result{}, err
		}
	} else {
		// List Services only in the current namespace
		if err := r.List(ctx, &services, client.InNamespace(req.Namespace)); err != nil {
			log.Error(err, "unable to list services")
			return reconcile.Result{}, err
		}
	}
	serviceNamespaceNames := make(map[string]struct{})
	for _, serviceEntry := range nwObj.Spec.ManualServices {
		serviceNamespaceNames[serviceEntry.Namespace+"/"+serviceEntry.Name] = struct{}{}
	}
	log.Info(fmt.Sprintf("Manually specified: %+v", serviceNamespaceNames))
	for _, service := range services.Items {
		_, manually_specified := serviceNamespaceNames[service.Namespace+"/"+service.Name]
		val, found := service.Annotations["unifi.engen.priv.no/firewall-group"]
		log.Info(fmt.Sprintf("%s %sv %+v %+v", service.Name, val, manually_specified, found))

		// if val, found := service.Annotations["unifi.engen.priv.no/firewall-group"]; (manually_specified || (found && val == nwObj.Name)) && service.Status.LoadBalancer.Ingress != nil {
		if (manually_specified || (found && val == nwObj.Name)) && service.Status.LoadBalancer.Ingress != nil {
			for _, ingress := range service.Status.LoadBalancer.Ingress {
				if ingress.IP != "" {
					ip := ingress.IP
					if isIPv6(ip) {
						ipv6 = append(ipv6, ip)
					} else {
						ipv4 = append(ipv4, ip)
					}
				}
			}
			if service.Spec.Ports != nil {
				for _, portSpec := range service.Spec.Ports {
					log.Info(fmt.Sprintf("portSpec: %+v", portSpec))
					log.Info(fmt.Sprintf("Port: %s %d", strconv.Itoa(int(portSpec.Port)), portSpec.Port))
					if portSpec.Protocol == "TCP" {
						if !slices.Contains(tcpports, strconv.Itoa(int(portSpec.Port))) {
							tcpports = append(tcpports, strconv.Itoa(int(portSpec.Port)))
						}
					}
					if portSpec.Protocol == "UDP" {
						if !slices.Contains(udpports, strconv.Itoa(int(portSpec.Port))) {
							udpports = append(udpports, strconv.Itoa(int(portSpec.Port)))
						}
					}
				}
			}
		}
	}
	nwObj.Status.ResolvedIPV4Addresses = ipv4
	nwObj.Status.ResolvedIPV6Addresses = ipv6
	nwObj.Status.ResolvedTCPPorts = tcpports
	nwObj.Status.ResolvedUDPPorts = udpports
	currentTime := metav1.Now()
	nwObj.Status.LastSyncTime = &currentTime
	nwObj.Status.SyncedWithUnifi = true
	if nwObj.Status.ResourcesManaged == nil {
		nwObj.Status.ResourcesManaged = &unifiv1beta1.FirewallGroupResourcesManaged{
			IPV4Object: &unifiv1beta1.NamedUnifiResource{
				ID:   "",
				Name: "",
			},
			IPV6Object: &unifiv1beta1.NamedUnifiResource{
				ID:   "",
				Name: "",
			},
			TCPPortsObject: &unifiv1beta1.NamedUnifiResource{
				ID:   "",
				Name: "",
			},
			UDPPortsObject: &unifiv1beta1.NamedUnifiResource{
				ID:   "",
				Name: "",
			},
		}
	}
	err = r.UnifiClient.Reauthenticate()
	if err != nil {
		return reconcile.Result{}, err
	}
	firewall_groups, err := r.UnifiClient.Client.ListFirewallGroup(context.Background(), r.UnifiClient.SiteID)
	if err != nil {
		log.Error(err, "Could not list network objects")
		return reconcile.Result{}, err
	}
	ipv4_name := "k8s-" + nwObj.Spec.Name + "-ipv4"
	ipv6_name := "k8s-" + nwObj.Spec.Name + "-ipv6"
	tcpports_name := "k8s-" + nwObj.Spec.Name + "-tcpports"
	udpports_name := "k8s-" + nwObj.Spec.Name + "-udpports"
	ipv4_done := false
	ipv6_done := false
	tcpports_done := false
	udpports_done := false
	for _, firewall_group := range firewall_groups {
		if firewall_group.Name == ipv4_name {
			if len(ipv4) == 0 {
				log.Info(fmt.Sprintf("Delete %s", ipv4_name))
				err := r.UnifiClient.Client.DeleteFirewallGroup(context.Background(), r.UnifiClient.SiteID, firewall_group.ID)
				if err != nil {
					msg := strings.ToLower(err.Error())
					log.Info(msg)
					if strings.Contains(msg, "api.err.objectreferredby") {
						log.Info("Firewall group is in use. Invoking workaround...!")
						firewall_group.GroupMembers = []string{"127.0.0.1"}
						firewall_group.Name = firewall_group.Name + "-deleted"
						_, updateerr := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
						if updateerr != nil {
							log.Error(updateerr, "Could neither delete or rename firewall group")
							return reconcile.Result{}, updateerr
						}
						nwObj.Status.ResourcesManaged.IPV4Object.Name = firewall_group.Name
					} else {
						log.Error(err, "Could not delete firewall group")
						return reconcile.Result{}, err
					}
				} else {
					nwObj.Status.ResourcesManaged.IPV4Object.Name = ""
					nwObj.Status.ResourcesManaged.IPV4Object.ID = ""
				}
				ipv4_done = true
			} else {
				if !reflect.DeepEqual(firewall_group.GroupMembers, ipv4) {
					firewall_group.GroupMembers = ipv4
					log.Info(fmt.Sprintf("Updating %s", ipv4_name))
					_, err := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
					if err != nil {
						log.Error(err, "Could not update firewall group")
						return reconcile.Result{}, err
					}
				}
				ipv4_done = true
			}
		}
		if firewall_group.Name == ipv6_name {
			if len(ipv6) == 0 {
				log.Info(fmt.Sprintf("Delete %s", ipv6_name))
				err := r.UnifiClient.Client.DeleteFirewallGroup(context.Background(), r.UnifiClient.SiteID, firewall_group.ID)
				if err != nil {
					msg := strings.ToLower(err.Error())
					log.Info(msg)
					if strings.Contains(msg, "api.err.objectreferredby") {
						log.Info("Firewall group is in use. Invoking workaround...!")
						firewall_group.GroupMembers = []string{"::1"}
						firewall_group.Name = firewall_group.Name + "-deleted"
						_, updateerr := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
						if updateerr != nil {
							log.Error(updateerr, "Could neither delete or rename firewall group")
							return reconcile.Result{}, updateerr
						}
						nwObj.Status.ResourcesManaged.IPV6Object.Name = firewall_group.Name
					} else {
						log.Error(err, "Could not delete firewall group")
						return reconcile.Result{}, err
					}
				} else {
					nwObj.Status.ResourcesManaged.IPV6Object.Name = ""
					nwObj.Status.ResourcesManaged.IPV6Object.ID = ""
				}
				ipv6_done = true
			} else {
				if !reflect.DeepEqual(firewall_group.GroupMembers, ipv6) {
					firewall_group.GroupMembers = ipv6
					log.Info(fmt.Sprintf("Updating %s", ipv6_name))
					_, err := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
					if err != nil {
						log.Error(err, "Could not update firewall group")
						return reconcile.Result{}, err
					}
				}
				ipv6_done = true
			}
		}
		if firewall_group.Name == tcpports_name {
			if len(tcpports) == 0 {
				log.Info(fmt.Sprintf("Delete %s", tcpports_name))
				err := r.UnifiClient.Client.DeleteFirewallGroup(context.Background(), r.UnifiClient.SiteID, firewall_group.ID)
				if err != nil {
					msg := strings.ToLower(err.Error())
					log.Info(msg)
					if strings.Contains(msg, "api.err.objectreferredby") {
						log.Info("Firewall group is in use. Invoking workaround...!")
						firewall_group.GroupMembers = []string{"0"}
						firewall_group.Name = firewall_group.Name + "-deleted"
						_, updateerr := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
						if updateerr != nil {
							log.Error(updateerr, "Could neither delete or rename firewall group")
							return reconcile.Result{}, updateerr
						}
						nwObj.Status.ResourcesManaged.TCPPortsObject.Name = firewall_group.Name
					} else {
						log.Error(err, "Could not delete firewall group")
						return reconcile.Result{}, err
					}
				} else {
					nwObj.Status.ResourcesManaged.TCPPortsObject.Name = ""
					nwObj.Status.ResourcesManaged.TCPPortsObject.ID = ""
				}
				tcpports_done = true
			} else {
				if !reflect.DeepEqual(firewall_group.GroupMembers, tcpports) {
					firewall_group.GroupMembers = tcpports
					log.Info(fmt.Sprintf("Updating %s", tcpports_name))
					_, err := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
					if err != nil {
						log.Error(err, "Could not update firewall group")
						return reconcile.Result{}, err
					}
				}
				tcpports_done = true
			}
		}
		if firewall_group.Name == udpports_name {
			if len(udpports) == 0 {
				log.Info(fmt.Sprintf("Delete %s", udpports_name))
				err := r.UnifiClient.Client.DeleteFirewallGroup(context.Background(), r.UnifiClient.SiteID, firewall_group.ID)
				if err != nil {
					msg := strings.ToLower(err.Error())
					log.Info(msg)
					if strings.Contains(msg, "api.err.objectreferredby") {
						log.Info("Firewall group is in use. Invoking workaround...!")
						firewall_group.GroupMembers = []string{"127.0.0.1"}
						firewall_group.Name = firewall_group.Name + "-deleted"
						_, updateerr := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
						if updateerr != nil {
							log.Error(updateerr, "Could neither delete or rename firewall group")
							return reconcile.Result{}, updateerr
						}
						nwObj.Status.ResourcesManaged.UDPPortsObject.Name = firewall_group.Name
					} else {
						log.Error(err, "Could not delete firewall group")
						return reconcile.Result{}, err
					}
				} else {
					nwObj.Status.ResourcesManaged.UDPPortsObject.Name = ""
					nwObj.Status.ResourcesManaged.UDPPortsObject.ID = ""
				}
				udpports_done = true
			} else {
				if !reflect.DeepEqual(firewall_group.GroupMembers, udpports) {
					firewall_group.GroupMembers = udpports
					log.Info(fmt.Sprintf("Updating %s", udpports_name))
					_, err := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
					if err != nil {
						log.Error(err, "Could not update firewall group")
						return reconcile.Result{}, err
					}
				}
				udpports_done = true
			}
		}
		if firewall_group.Name == ipv4_name+"-deleted" && len(ipv4) > 0 {
			firewall_group.Name = ipv4_name
			firewall_group.GroupMembers = ipv4
			log.Info(fmt.Sprintf("Creating %s (from previously deleted)", ipv4_name))
			_, err := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
			if err != nil {
				log.Error(err, "Could not update firewall group")
				return reconcile.Result{}, err
			}
			nwObj.Status.ResourcesManaged.IPV4Object.Name = firewall_group.Name
			ipv4_done = true
		}
		if firewall_group.Name == ipv6_name+"-deleted" && len(ipv6) > 0 {
			firewall_group.Name = ipv6_name
			firewall_group.GroupMembers = ipv6
			log.Info(fmt.Sprintf("Creating %s (from previously deleted)", ipv6_name))
			_, err := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
			if err != nil {
				log.Error(err, "Could not update firewall group")
				return reconcile.Result{}, err
			}
			nwObj.Status.ResourcesManaged.IPV4Object.Name = firewall_group.Name
			ipv6_done = true
		}
		if firewall_group.Name == tcpports_name+"-deleted" && len(tcpports) > 0 {
			firewall_group.Name = tcpports_name
			firewall_group.GroupMembers = tcpports
			log.Info(fmt.Sprintf("Creating %s (from previously deleted)", tcpports_name))
			_, err := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
			if err != nil {
				log.Error(err, "Could not update firewall group")
				return reconcile.Result{}, err
			}
			nwObj.Status.ResourcesManaged.TCPPortsObject.Name = firewall_group.Name
			tcpports_done = true
		}
		if firewall_group.Name == udpports_name+"-deleted" && len(udpports) > 0 {
			firewall_group.Name = udpports_name
			firewall_group.GroupMembers = udpports
			log.Info(fmt.Sprintf("Creating %s (from previously deleted)", udpports_name))
			_, err := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
			if err != nil {
				log.Error(err, "Could not update firewall group")
				return reconcile.Result{}, err
			}
			nwObj.Status.ResourcesManaged.UDPPortsObject.Name = firewall_group.Name
			udpports_done = true
		}
	}
	if len(ipv4) > 0 && !ipv4_done {
		log.Info(fmt.Sprintf("Creating %s", ipv4_name))
		var firewall_group goUnifi.FirewallGroup
		firewall_group.Name = ipv4_name
		firewall_group.SiteID = r.UnifiClient.SiteID
		firewall_group.GroupMembers = ipv4
		firewall_group.GroupType = "address-group"
		firewall_group_result, err := r.UnifiClient.Client.CreateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
		log.Info(fmt.Sprintf("%+v", firewall_group_result))
		if err != nil {
			log.Error(err, "Could not create firewall group")
			return reconcile.Result{}, err
		} else {
			firewall_group = *firewall_group_result
		}

		log.Info(fmt.Sprintf("ID and name: %s %s", firewall_group.ID, firewall_group.Name))
		log.Info(fmt.Sprintf("%+v", firewall_group))
		nwObj.Status.ResourcesManaged.IPV4Object.ID = firewall_group.ID
		nwObj.Status.ResourcesManaged.IPV4Object.Name = firewall_group.Name
	}
	if len(ipv6) > 0 && !ipv6_done {
		log.Info(fmt.Sprintf("Creating %s", ipv6_name))
		var firewall_group goUnifi.FirewallGroup
		firewall_group.Name = ipv6_name
		firewall_group.SiteID = r.UnifiClient.SiteID
		firewall_group.GroupMembers = ipv6
		firewall_group.GroupType = "ipv6-address-group"
		firewall_group_result, err := r.UnifiClient.Client.CreateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
		log.Info(fmt.Sprintf("%+v", firewall_group_result))
		if err != nil {
			log.Error(err, "Could not create firewall group")
			return reconcile.Result{}, err
		} else {
			firewall_group = *firewall_group_result
		}
		nwObj.Status.ResourcesManaged.IPV6Object.ID = firewall_group.ID
		nwObj.Status.ResourcesManaged.IPV6Object.Name = firewall_group.Name

	}
	if len(tcpports) > 0 && !tcpports_done {
		log.Info(fmt.Sprintf("Creating %s", tcpports_name))
		var firewall_group goUnifi.FirewallGroup
		firewall_group.Name = tcpports_name
		firewall_group.SiteID = r.UnifiClient.SiteID
		firewall_group.GroupMembers = tcpports
		firewall_group.GroupType = "port-group"
		log.Info(fmt.Sprintf("Trying to apply: %+v", firewall_group))
		firewall_group_result, err := r.UnifiClient.Client.CreateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
		if err != nil {
			log.Error(err, "Could not create firewall group")
			return reconcile.Result{}, err
		} else {
			firewall_group = *firewall_group_result
		}
		nwObj.Status.ResourcesManaged.TCPPortsObject.ID = firewall_group.ID
		nwObj.Status.ResourcesManaged.TCPPortsObject.Name = firewall_group.Name
	}
	if len(udpports) > 0 && !udpports_done {
		log.Info(fmt.Sprintf("Creating %s", udpports_name))
		var firewall_group goUnifi.FirewallGroup
		firewall_group.Name = udpports_name
		firewall_group.SiteID = r.UnifiClient.SiteID
		firewall_group.GroupMembers = udpports
		firewall_group.GroupType = "port-group"
		log.Info(fmt.Sprintf("Trying to apply: %+v", firewall_group))
		firewall_group_result, err := r.UnifiClient.Client.CreateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
		log.Info(fmt.Sprintf("%+v", firewall_group_result))
		if err != nil {
			log.Error(err, "Could not create firewall group")
			return reconcile.Result{}, err
		} else {
			firewall_group = *firewall_group_result
		}
		nwObj.Status.ResourcesManaged.UDPPortsObject.ID = firewall_group.ID
		nwObj.Status.ResourcesManaged.UDPPortsObject.Name = firewall_group.Name
	}
	log.Info(fmt.Sprintf("Updating status for %s: %+v", nwObj.Name, nwObj.Status))
	if err := r.Status().Update(ctx, &nwObj); err != nil {
		log.Error(err, "unable to update FirewallGroup status")
		return reconcile.Result{}, err
	}

	log.Info("Successfully updated FirewallGroup status with collected IP addresses and ports")

	return reconcile.Result{}, nil
}
func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}
func (r *FirewallGroupReconciler) mapServiceToFirewallGroups(ctx context.Context, obj client.Object) []reconcile.Request {
	var requests []reconcile.Request
	service, ok := obj.(*corev1.Service)
	if !ok {
		return requests
	}

	var allFirewallGroups unifiv1beta1.FirewallGroupList

	if err := r.List(ctx, &allFirewallGroups); err != nil {
		return nil
	}

	for _, fwg := range allFirewallGroups.Items {
		if fwg.Spec.MatchServicesInAllNamespaces || fwg.Namespace == service.Namespace {
			annotationKey := "unifi.engen.priv.no/firewall-group"
			annotationVal := fwg.Name
			if val, ok := service.Annotations[annotationKey]; ok && (annotationVal == "" || val == annotationVal) {
				requests = append(requests, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      fwg.Name,
						Namespace: fwg.Namespace,
					},
				})
			}
		}
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&unifiv1beta1.FirewallGroup{}).
		Named("firewallgroup").
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(r.mapServiceToFirewallGroups),
		).
		Complete(r)
}
