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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

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
func (r *FirewallRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// TODO(user): your logic here

	cfg, err := r.ConfigLoader.GetConfig(ctx, "unifi-operator-config")
	if err != nil {
		return ctrl.Result{}, err
	}

	defaultNs := cfg.Data["defaultNamespace"]
	log.Info(defaultNs)

	err = r.UnifiClient.Reauthenticate()
	if err != nil {
		return ctrl.Result{}, err
	}

	var zoneCRDs unifiv1beta1.FirewallZoneList
	var networkCRDs unifiv1beta1.NetworkconfigurationList

	err = r.List(ctx, &zoneCRDs, client.InNamespace(defaultNs))
	if err != nil {
		log.Error(err, "Could not list firewall zones")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}

	zoneCRDNames := make(map[string]struct{})

	for _, zoneCRD := range zoneCRDs.Items {
		zoneCRDNames[zoneCRD.Name] = struct{}{}
	}

	err = r.List(ctx, &networkCRDs, client.InNamespace(defaultNs))
	if err != nil {
		log.Error(err, "Could not list networks")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}

	networkCRDNames := make(map[string]struct{})

	for _, networkCRD := range networkCRDs.Items {
		networkCRDNames[networkCRD.Name] = struct{}{}
	}

	var firewallRule unifiv1beta1.FirewallRule

	if err := r.Get(ctx, req.NamespacedName, &firewallRule); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Info(firewallRule.Spec.Name)

	return ctrl.Result{}, nil
}

func (r *FirewallRuleReconciler) mapFirewallGroupToFirewallRules(ctx context.Context, obj client.Object) []ctrl.Request {
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
		if rule.Spec.MatchFirewallGroupsInAllNamespaces || rule.Namespace == service.Namespace {
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
