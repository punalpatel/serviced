// Copyright 2014 The Serviced Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"path"
	"sync"
	"time"

	"github.com/control-center/serviced/coordinator/client"

	"github.com/control-center/serviced/domain/service"
	"github.com/control-center/serviced/domain/servicestate"
	"github.com/zenoss/glog"
)

const (
	zkHost = "/hosts"
)

// HostState is the zookeeper node for storing service instance information
// per host
type HostState struct {
	HostID         string
	ServiceID      string
	ServiceStateID string
	DesiredState   int
	version        interface{}
}

// NewHostState instantiates a new HostState node for client.Node
func NewHostState(state *servicestate.ServiceState) *HostState {
	return &HostState{
		HostID:         state.HostID,
		ServiceID:      state.ServiceID,
		ServiceStateID: state.ID,
		DesiredState:   int(service.SVCRun),
	}
}

// Version implements client.Node
func (node *HostState) Version() interface{} {
	return node.version
}

// SetVersion implements client.Node
func (node *HostState) SetVersion(version interface{}) {
	node.version = version
}

// HostHandler is the handler for running the HostListener
type HostStateHandler interface {
	PullImage(cancel <-chan time.Time, imageID string) (string, error)
	AttachService(*service.Service, *servicestate.ServiceState, func(string)) error
	StartService(*service.Service, *servicestate.ServiceState, func(string)) error
	PauseService(*service.Service, *servicestate.ServiceState) error
	ResumeService(*service.Service, *servicestate.ServiceState) error
	StopService(*servicestate.ServiceState) error
}

// HostStateListener is the listener for monitoring service instances
type HostStateListener struct {
	conn     client.Connection
	handler  HostStateHandler
	hostID   string
	nodelock sync.Mutex
	done     bool
}

// NewHostListener instantiates a HostListener object
func NewHostStateListener(handler HostStateHandler, hostID string) *HostStateListener {
	return &HostStateListener{
		handler:  handler,
		hostID:   hostID,
		nodelock: sync.Mutex{},
		done:     false,
	}
}

// GetConnection implements zzk.Listener
func (l *HostStateListener) SetConnection(conn client.Connection) { l.conn = conn }

// GetPath implements zzk.Listener
func (l *HostStateListener) GetPath(nodes ...string) string {
	parts := append([]string{zkHost, l.hostID, "instances"}, nodes...)
	return path.Join(parts...)
}

// Look up the service data from a service node.
func (l *HostStateListener) getService(svcNode *ServiceNode) (*service.Service, error) {
	return &service.Service{}, nil
}

// Ready implements zzk.Listener
func (l *HostStateListener) Ready() error {
	return nil
}

// Done removes the ephemeral node from the host registry
func (l *HostStateListener) Done() {
}

// PostProcess implements zzk.Listener
func (l *HostStateListener) PostProcess(p map[string]struct{}) {}

// Spawn listens for changes in the host state and manages running instances
func (l *HostStateListener) Spawn(shutdown <-chan interface{}, stateID string) {
	var processDone <-chan struct{}
	var processLock sync.Mutex

	// Get the HostState node
	hpth := l.GetPath(stateID)
	var hs HostState
	if err := l.conn.Get(hpth, &hs); err != nil {
		glog.Errorf("Could not load host instance %s on host %s: %s", stateID, l.hostID, err)
		l.conn.Delete(hpth)
		return
	}
	defer removeInstance(l.conn, "", hs.HostID, hs.ServiceID, hs.ServiceStateID)
	// Get the ServiceState node
	var ss servicestate.ServiceState
	if err := l.conn.Get(servicepath(hs.ServiceID, hs.ServiceStateID), &ServiceStateNode{ServiceState: &ss}); err != nil {
		glog.Errorf("Could not load service instance %s for service %s on host %s: %s", hs.ServiceStateID, hs.ServiceID, hs.HostID, err)
		return
	}
	defer l.stopInstance(&processLock, &ss)

	done := make(chan struct{})
	defer func() { close(done) }()
	for {
		// Get the HostState instance
		hsEvt, err := l.conn.GetW(hpth, &hs, done)
		if err != nil {
			glog.Errorf("Could not load host instance %s on host %s: %s", stateID, l.hostID, err)
			return
		}
		// Get the ServiceState instance
		ssEvt, err := l.conn.GetW(servicepath(hs.ServiceID, stateID), &ServiceStateNode{ServiceState: &ss}, done)
		if err != nil {
			glog.Errorf("Could not load service state %s for service %s on host %s: %s", stateID, hs.ServiceID, l.hostID, err)
			return
		}
		// Get the service
		var svcNode ServiceNode
		if err := l.conn.Get(servicepath(hs.ServiceID), &svcNode); err != nil {
			glog.Errorf("Could not load service %s for service instance %s on host %s: %s", hs.ServiceID, stateID, l.hostID, err)
			return
		}

		// Process the desired state
		glog.V(2).Infof("Processing %s (%s); Desired State: %d", svcNode.Name, svcNode.ID, hs.DesiredState)
		switch service.DesiredState(hs.DesiredState) {
		case service.SVCRun:
			var err error
			if !ss.IsRunning() {
				// process has stopped
				glog.Infof("Starting a new instance for %s (%s): %s", svcNode.Name, svcNode.ID, stateID)
				if processDone, err = l.startInstance(shutdown, &processLock, &svcNode, &ss); err != nil {
					glog.Errorf("Could not start service instance %s for service %s on host %s: %s", hs.ServiceStateID, hs.ServiceID, hs.HostID, err)
					return
				}
			} else if processDone == nil {
				glog.Infof("Attaching to instance %s for %s (%s) via %s", stateID, svcNode.Name, svcNode.ID, ss.DockerID)
				if processDone, err = l.attachInstance(&processLock, &svcNode, &ss); err != nil {
					glog.Errorf("Could not start service instance %s for service %s on host %s: %s", hs.ServiceStateID, hs.ServiceID, hs.HostID, err)
					return
				}
			}
			if ss.IsPaused() {
				glog.Infof("Resuming paused instance %s for service %s (%s)", stateID, svcNode.Name, svcNode.ID)
				if err := l.resumeInstance(&svcNode, &ss); err != nil {
					glog.Errorf("Could not resume paused instance %s for service %s (%s): %s", stateID, svcNode.Name, svcNode.ID, err)
					return
				}
			}
		case service.SVCPause:
			if !ss.IsPaused() {
				if err := l.pauseInstance(&svcNode, &ss); err != nil {
					glog.Errorf("Could not pause instance %s for service %s (%s): %s", stateID, svcNode.Name, svcNode.ID, err)
					return
				}
			}
		case service.SVCStop:
			return
		default:
			glog.V(2).Infof("Unhandled state (%d) of instance %s for service %s (%s)", hs.DesiredState, stateID, svcNode.Name, svcNode.ID, err)
		}

		select {
		case <-processDone:
			glog.Infof("Process ended for instance %s for service %s (%s)", stateID, svcNode.Name, svcNode.ID)
			processDone = nil // CC-1341 - once the process exits, don't read this channel again
		case e := <-hsEvt:
			glog.V(3).Infof("Host instance %s for service %s (%s) received an event: %+v", stateID, svcNode.Name, svcNode.ID, e)
			if e.Type == client.EventNodeDeleted {
				return
			}
		case e := <-ssEvt:
			glog.V(3).Infof("Service instance %s for service %s (%s) received an event: %+v", stateID, svcNode.Name, svcNode.ID, e)
			if e.Type == client.EventNodeDeleted {
				return
			}
		case <-shutdown:
			glog.V(2).Infof("Host instance %s for service %s (%s) received signal to shutdown", stateID, svcNode.Name, svcNode.ID)
			return
		}

		close(done)
		done = make(chan struct{})
	}
}

func (l *HostStateListener) terminateInstance(locker sync.Locker, done chan<- struct{}) func(string) {
	return func(stateID string) {
		defer locker.Unlock()
		defer close(done)
		glog.V(3).Infof("Received process done signal for %s", stateID)
		terminated := time.Now()
		setTerminated := func(_ *HostState, ssdata *servicestate.ServiceState) {
			ssdata.Terminated = terminated
			ssdata.DockerID = ""
		}
		if err := updateInstance(l.conn, "", l.hostID, stateID, setTerminated); err != nil {
			glog.Warningf("Could not update instance %s with the time terminated (%s): %s", stateID, terminated, err)
		}
	}
}

func (l *HostStateListener) startInstance(shutdown <-chan interface{}, locker sync.Locker, svcNode *ServiceNode, state *servicestate.ServiceState) (<-chan struct{}, error) {
	svc, err := l.getService(svcNode)
	if err != nil {
		glog.Errorf("Could not look up service data for service node %s", svcNode.Name)
		return nil, err
	}

	cancelC := make(chan struct{})
	defer close(cancelC)
	timeoutC := make(chan time.Time)
	go func() {
		select {
		case <-shutdown:
			close(timeoutC)
		case <-cancelC:
		}
	}()
	// Pull the image
	uuid, err := l.handler.PullImage(timeoutC, svc.ImageID)
	if err != nil {
		glog.Errorf("Error trying to pull image %s for service %s (%s): %s", svc.ImageID, svc.Name, svc.ID, err)
		return nil, err
	}
	state.ImageRepo = svc.ImageID
	state.ImageUUID = uuid
	done := make(chan struct{})
	locker.Lock()
	if err := l.handler.StartService(svc, state, l.terminateInstance(locker, done)); err != nil {
		glog.Errorf("Error trying to start service instance %s for service %s (%s): %s", state.ID, svc.Name, svc.ID, err)
		return nil, err
	}
	return done, UpdateServiceState(l.conn, state)
}

func (l *HostStateListener) attachInstance(locker sync.Locker, svcNode *ServiceNode, state *servicestate.ServiceState) (<-chan struct{}, error) {
	svc, err := l.getService(svcNode)
	if err != nil {
		glog.Errorf("Could not look up service data for service node %s", svcNode.Name)
		return nil, err
	}

	done := make(chan struct{})
	locker.Lock()
	if err := l.handler.AttachService(svc, state, l.terminateInstance(locker, done)); err != nil {
		glog.Errorf("Error trying to attach to service instance %s for service %s (%s): %s", state.ID, svc.Name, svc.ID, err)
		return nil, err
	}
	return done, UpdateServiceState(l.conn, state)
}

func (l *HostStateListener) pauseInstance(svcNode *ServiceNode, state *servicestate.ServiceState) error {
	glog.Infof("Pausing service instance %s for service %s (%s)", state.ID, svcNode.Name, svcNode.ID)

	svc, err := l.getService(svcNode)
	if err != nil {
		glog.Errorf("Could not look up service data for service node %s", svcNode.Name)
		return err
	}

	if err := l.handler.PauseService(svc, state); err != nil {
		glog.Errorf("Could not pause service instance %s: %s", state.ID, err)
		return err
	}
	setPaused := func(_ *HostState, ssdata *servicestate.ServiceState) {
		ssdata.Paused = true
	}
	return updateInstance(l.conn, "", l.hostID, state.ID, setPaused)
}

func (l *HostStateListener) resumeInstance(svcNode *ServiceNode, state *servicestate.ServiceState) error {
	svc, err := l.getService(svcNode)
	if err != nil {
		glog.Errorf("Could not look up service data for service node %s", svcNode.Name)
		return err
	}

	if err := l.handler.ResumeService(svc, state); err != nil {
		glog.Errorf("Could not resume service instance %s: %s", state.ID, err)
		return err
	}
	unsetPaused := func(_ *HostState, ssdata *servicestate.ServiceState) {
		ssdata.Paused = false
	}
	return updateInstance(l.conn, "", l.hostID, state.ID, unsetPaused)
}

// stopInstance stops instance and signals done.  caller is expected to check for nil state
func (l *HostStateListener) stopInstance(locker sync.Locker, state *servicestate.ServiceState) error {
	if err := l.handler.StopService(state); err != nil {
		glog.Errorf("Could not stop service instance %s: %s", state.ID, err)
		return err
	}
	// wait for the process to be done
	glog.V(3).Infof("waiting for service instance %s to be updated", state.ID)
	locker.Lock()
	locker.Unlock()
	return nil
}
