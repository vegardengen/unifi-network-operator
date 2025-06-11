package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	//	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	//	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	//	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	//	"sigs.k8s.io/controller-runtime/pkg/source"

	goUnifi "github.com/vegardengen/go-unifi/unifi"
	//	unifiv1beta1 "github.com/vegardengen/unifi-network-operator/api/v1beta1"
	"github.com/vegardengen/unifi-network-operator/internal/config"
	"github.com/vegardengen/unifi-network-operator/internal/unifi"
)

type PortForwardReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	UnifiClient  *unifi.UnifiClient
	ConfigLoader *config.ConfigLoaderType
}

// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=portforwards,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=portforwards/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=unifi.engen.priv.no,resources=portforwards/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=services,verbs=list;get;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=list;get;watch

func (r *PortForwardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	var svc corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	annotation := svc.Annotations["portforward.unifi.engen.priv.no/forward"]
	err := r.UnifiClient.Reauthenticate()
	if err != nil {
		log.Error(err, "Failed to authenticate to Unifi")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}

	portforwards, err := r.UnifiClient.Client.ListPortForward(context.Background(), r.UnifiClient.SiteID)
	if err != nil {
		log.Error(err, "Failed to list PortForfards")
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
	}
	portforwardnames := make(map[string]int)
	for i, portforward := range portforwards {
		portforwardnames[portforward.Name] = i
	}
	if annotation == "" {
		for _, port := range svc.Spec.Ports {
			portforwardname := "k8s-forward-" + svc.Name + "-" + port.Name
			if i, found := portforwardnames[portforwardname]; found {
				log.Info(fmt.Sprintf("Cleaning up old portfoward for service %s/%s", svc.Namespace, svc.Name))
				if err := r.UnifiClient.Client.DeletePortForward(context.Background(), r.UnifiClient.SiteID, portforwards[i].ID); err != nil {
					log.Error(err, "Could not delete portforward")
					return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
				}
			}
		}
		return ctrl.Result{}, nil
	}

	portMap := make(map[string]int)
	entries := strings.Split(annotation, ";")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		for _, port := range svc.Spec.Ports {
			if parts[0] == port.Name {
				if len(parts) == 1 {
					portMap[parts[0]] = int(port.Port)
				} else if len(parts) == 2 {
					extPort, err := strconv.Atoi(parts[1])
					if err != nil {
						log.Error(err, "Invalid external port", "entry", entry)
						continue
					}
					portMap[parts[0]] = extPort
				}
			}
		}
	}

	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		log.Info("No LoadBalancer IP for Service", "service", svc.Name)
		return ctrl.Result{}, nil
	}

	ip := svc.Status.LoadBalancer.Ingress[0].IP

	for _, port := range svc.Spec.Ports {
		extPort, found := portMap[port.Name]

		if found {

			log.Info("Setting up port forward",
				"externalPort", extPort,
				"internalPort", port.Port,
				"ip", ip,
				"protocol", port.Protocol)
		}
		portforwardname := "k8s-forward-" + svc.Name + "-" + port.Name
		log.Info(fmt.Sprintf("Should handle %s", portforwardname))
		if portforwardindex, found := portforwardnames[portforwardname]; found {
			if portforwards[portforwardindex].DstPort == fmt.Sprintf("%d", portMap[port.Name]) && portforwards[portforwardindex].Fwd == ip && portforwards[portforwardindex].FwdPort == fmt.Sprintf("%d", port.Port) {
				log.Info("Portforward already exists and is correct")
			} else {
				log.Info("Exists, but need to update")
				portforwards[portforwardindex].DstPort = fmt.Sprintf("%d", portMap[port.Name])
				portforwards[portforwardindex].FwdPort = fmt.Sprintf("%d", port.Port)
				portforwards[portforwardindex].Fwd = ip
				if _, err := r.UnifiClient.Client.UpdatePortForward(context.Background(), r.UnifiClient.SiteID, &portforwards[portforwardindex]); err != nil {
					log.Error(err, fmt.Sprintf("Failed to update portforward %s", portforwardname))
					return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
				}
			}
		} else {
			_, err := r.UnifiClient.Client.CreatePortForward(context.Background(), r.UnifiClient.SiteID, &goUnifi.PortForward{Name: portforwardname, PfwdInterface: "wan", Src: "any", Log: false, DestinationIPs: []goUnifi.PortForwardDestinationIPs{}, Enabled: true, Fwd: ip, DestinationIP: "any", Proto: "tcp", DstPort: fmt.Sprintf("%d", portMap[port.Name]), SiteID: r.UnifiClient.SiteID, FwdPort: fmt.Sprintf("%d", port.Port)})
			if err != nil {
				log.Error(err, "Portforward could not be created")
				return ctrl.Result{RequeueAfter: 10 * time.Minute}, err
			}
		}

	}
	return ctrl.Result{}, nil
}

func (r *PortForwardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}
