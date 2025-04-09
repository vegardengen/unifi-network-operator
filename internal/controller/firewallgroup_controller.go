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
	"net"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	unifiv1beta1 "github.com/vegardengen/unifi-network-operator/api/v1beta1"
	goUnifi "github.com/vegardengen/go-unifi/unifi"
	"github.com/vegardengen/unifi-network-operator/internal/unifi"
)

// FirewallGroupReconciler reconciles a FirewallGroup object
type FirewallGroupReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	UnifiClient *unifi.UnifiClient
}

// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallgroups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallgroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=firewallgroups/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the FirewallGroup object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile



func (r *FirewallGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	var nwObj unifiv1beta1.FirewallGroup
        if err := r.Get(ctx, req.NamespacedName, &nwObj); err != nil {
           return ctrl.Result{}, client.IgnoreNotFound(err)
        }
	log.Info(nwObj.Spec.Name)
	var ipv4, ipv6 []string
        
	for _,addressEntry := range nwObj.Spec.ManualAddresses {
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
		 mask,_ := net.Mask.Size()
	         log.Info(fmt.Sprintf("Ipv6 Net: %s", net))
	         ipv6 = append(ipv6, addr.Mask(net.Mask).String() + "/" + fmt.Sprint(mask))
	       }
	     } else {
		     log.Error(err,fmt.Sprintf("Could not parse: %s", addressEntry))
		     return ctrl.Result{}, err
             }
	   }
        }
        firewall_groups, err := r.UnifiClient.Client.ListFirewallGroup(context.Background(), r.UnifiClient.SiteID)
	if err != nil {
          log.Error(err,"Could not list network objects")
	  return ctrl.Result{}, err
	}
	ipv4_name := "k8s-"+nwObj.Spec.Name+"-ipv4"
	ipv6_name := "k8s-"+nwObj.Spec.Name+"-ipv6"
	ipv4_done := false
	ipv6_done := false
	for _,firewall_group := range firewall_groups {
	    if firewall_group.Name == ipv4_name {
	       if(len(ipv4) == 0) {
		  log.Info(fmt.Sprintf("Delete %s", ipv4_name))
		  err := r.UnifiClient.Client.DeleteFirewallGroup(context.Background(), r.UnifiClient.SiteID, firewall_group.ID)
		  if err != nil {
	            log.Error(err,"Could not delete firewall group")
	            return ctrl.Result{}, err
		  }
		  ipv4_done = true
	       } else {
		  if !reflect.DeepEqual(firewall_group.GroupMembers, ipv4) {
		    firewall_group.GroupMembers = ipv4
		    log.Info(fmt.Sprintf("Updating %s", ipv4_name))
		    _, err := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
		    if err != nil {
	              log.Error(err,"Could not update firewall group")
	              return ctrl.Result{}, err
		    }
		  }
		  ipv4_done = true
	       }
	     }
	    if firewall_group.Name == ipv6_name {
	       if(len(ipv6) == 0) {
		  log.Info(fmt.Sprintf("Delete %s", ipv6_name))
		  err := r.UnifiClient.Client.DeleteFirewallGroup(context.Background(), r.UnifiClient.SiteID, firewall_group.ID)
		  if err != nil {
	            log.Error(err,"Could not delete firewall group")
	            return ctrl.Result{}, err
		  }
		  ipv6_done = true
	       } else {
		  if !reflect.DeepEqual(firewall_group.GroupMembers, ipv6) {
		    firewall_group.GroupMembers = ipv6
		    log.Info(fmt.Sprintf("Updating %s", ipv6_name))
		    _, err := r.UnifiClient.Client.UpdateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
		    if err != nil {
	              log.Error(err,"Could not update firewall group")
	              return ctrl.Result{}, err
		    }
		  }
		  ipv6_done = true
	       }
	     }
	}
	if len(ipv4) > 0 && !ipv4_done {
	  log.Info(fmt.Sprintf("Creating %s", ipv4_name))
	  var firewall_group goUnifi.FirewallGroup
	  firewall_group.Name=ipv4_name
	  firewall_group.SiteID=r.UnifiClient.SiteID
	  firewall_group.GroupMembers = ipv4
	  firewall_group.GroupType = "address-group"
	   _, err := r.UnifiClient.Client.CreateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
	   if err != nil {
	      log.Error(err,"Could not create firewall group")
	      return ctrl.Result{}, err
	   }
	}
	if len(ipv6) > 0 && !ipv6_done {
	  log.Info(fmt.Sprintf("Creating %s", ipv6_name))
	  var firewall_group goUnifi.FirewallGroup
	  firewall_group.Name=ipv6_name
	  firewall_group.SiteID=r.UnifiClient.SiteID
	  firewall_group.GroupMembers = ipv6
	  firewall_group.GroupType = "ipv6-address-group"
	   _, err := r.UnifiClient.Client.CreateFirewallGroup(context.Background(), r.UnifiClient.SiteID, &firewall_group)
	   if err != nil {
	      log.Error(err,"Could not create firewall group")
	      return ctrl.Result{}, err
	   }
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&unifiv1beta1.FirewallGroup{}).
		Named("firewallgroup").
		Complete(r)
}
