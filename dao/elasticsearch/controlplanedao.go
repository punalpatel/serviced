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

// Package agent implements a service that runs on a serviced node. It is
// responsible for ensuring that a particular node is running the correct services
// and reporting the state and health of those services back to the master
// serviced.

package elasticsearch

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/control-center/serviced/coordinator/client"
	"github.com/control-center/serviced/dao"
	"github.com/control-center/serviced/datastore"
	"github.com/control-center/serviced/dfs"
	"github.com/control-center/serviced/domain/service"
	"github.com/control-center/serviced/facade"
	"github.com/control-center/serviced/zzk"
	zkdocker "github.com/control-center/serviced/zzk/docker"
	zkservice "github.com/control-center/serviced/zzk/service"
	"github.com/zenoss/elastigo/api"
	"github.com/zenoss/glog"
)

const (
	DOCKER_ENDPOINT string = "unix:///var/run/docker.sock"
)

//assert interface
var _ dao.ControlPlane = &ControlPlaneDao{}

type ControlPlaneDao struct {
	hostName       string
	port           int
	varpath        string
	vfs            string
	dfs            *dfs.DistributedFileSystem
	facade         *facade.Facade
	dockerRegistry string
	backupLock     sync.RWMutex
	restoreLock    sync.RWMutex
	serviceLock    *serviceLock
}

type serviceLock struct {
	mutex sync.RWMutex
	f     *facade.Facade
	locks map[client.Connection]client.Lock
}

func newServiceLock(f *facade.Facade) *serviceLock {
	return &serviceLock{f: f, locks: make(map[client.Connection]client.Lock)}
}

func (l *serviceLock) Lock() error {
	l.mutex.Lock()
	pools, err := l.f.GetResourcePools(datastore.Get())
	if err != nil {
		l.mutex.Unlock()
		return err
	} else if pools == nil {
		return nil
	}

	for _, p := range pools {
		conn, err := zzk.GetLocalConnection(zzk.GeneratePoolPath(p.ID))
		if err != nil {
			glog.Errorf("Could not acquire connection: %s", err)
			l.Unlock()
			return err
		}

		lock := zkservice.ServiceLock(conn)
		if err := lock.Lock(); err != nil {
			glog.Errorf("Could not acquire lock: %s", err)
			l.Unlock()
			return err
		}

		l.locks[conn] = lock
	}

	return nil
}

func (l *serviceLock) Unlock() error {
	defer l.mutex.Unlock()
	for conn, lock := range l.locks {
		if err := lock.Unlock(); err != nil {
			glog.Errorf("Could not remove lock; cycling connection %v: %s", conn, err)
			conn.Close()
		}
	}
	l.locks = make(map[client.Connection]client.Lock)
	return nil
}

func serviceGetter(ctx datastore.Context, f *facade.Facade) service.GetService {
	return func(svcID string) (service.Service, error) {
		svc, err := f.GetService(ctx, svcID)
		if err != nil {
			return service.Service{}, err
		}
		return *svc, nil
	}
}

func childFinder(ctx datastore.Context, f *facade.Facade) service.FindChildService {
	return func(svcID, childName string) (service.Service, error) {
		svc, err := f.FindChildService(ctx, svcID, childName)
		if err != nil {
			return service.Service{}, err
		}
		return *svc, nil
	}
}

func (this *ControlPlaneDao) Action(request dao.AttachRequest, unused *int) error {
	ctx := datastore.Get()
	svc, err := this.facade.GetService(ctx, request.Running.ServiceID)
	if err != nil {
		return err
	}

	var command []string
	if request.Command == "" {
		return fmt.Errorf("missing command")
	}

	if err := svc.EvaluateActionsTemplate(serviceGetter(ctx, this.facade), childFinder(ctx, this.facade), request.Running.InstanceID); err != nil {
		return err
	}

	action, ok := svc.Actions[request.Command]
	if !ok {
		return fmt.Errorf("action not found for service %s: %s", svc.ID, request.Command)
	}

	command = append([]string{action}, request.Args...)
	req := zkdocker.Action{
		HostID:   request.Running.HostID,
		DockerID: request.Running.DockerID,
		Command:  command,
	}

	conn, err := zzk.GetLocalConnection(zzk.GeneratePoolPath(svc.PoolID))
	if err != nil {
		return err
	}

	_, err = zkdocker.SendAction(conn, &req)
	return err
}

func (this *ControlPlaneDao) RestartService(serviceID string, unused *int) error {
	return dao.ControlPlaneError{Msg: "unimplemented"}
}

// Create a elastic search control center data access object
func NewControlPlaneDao(hostName string, port int, facade *facade.Facade, maxdfstimeout time.Duration, dockerRegistry string) (*ControlPlaneDao, error) {
	glog.V(0).Infof("Opening ElasticSearch ControlPlane Dao: hostName=%s, port=%d", hostName, port)
	api.Domain = hostName
	api.Port = strconv.Itoa(port)

	dao := &ControlPlaneDao{
		hostName:       hostName,
		port:           port,
		dockerRegistry: dockerRegistry,
		serviceLock:    newServiceLock(facade),
	}
	if dfs, err := dfs.NewDistributedFileSystem(dao, facade, maxdfstimeout); err != nil {
		return nil, err
	} else {
		dao.dfs = dfs
	}

	return dao, nil
}

func NewControlSvc(hostName string, port int, facade *facade.Facade, varpath, vfs string, maxdfstimeout time.Duration, dockerRegistry string) (*ControlPlaneDao, error) {
	glog.V(2).Info("calling NewControlSvc()")
	defer glog.V(2).Info("leaving NewControlSvc()")

	s, err := NewControlPlaneDao(hostName, port, facade, maxdfstimeout, dockerRegistry)
	if err != nil {
		return nil, err
	}

	//Used to bridge old to new
	s.facade = facade

	s.varpath = varpath
	s.vfs = vfs

	// create the account credentials
	if err = createSystemUser(s); err != nil {
		return nil, err
	}

	return s, nil
}
