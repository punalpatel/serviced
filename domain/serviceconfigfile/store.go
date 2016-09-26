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

package serviceconfigfile

import (
	"fmt"

	"github.com/control-center/serviced/datastore"
	"github.com/zenoss/elastigo/search"
)

//NewStore creates a Service Config File store
func NewStore() Store {
	return &storeImpl{}
}

//Store type for interacting with Service Config File persistent storage
type Store interface {
	datastore.EntityStore

	GetConfigFiles(ctx datastore.Context, tenantID string, svcPath string) ([]*SvcConfigFile, error)
	GetConfigFile(ctx datastore.Context, tenantID, svcPath, filename string) (*SvcConfigFile, error)
}

type storeImpl struct {
	datastore.DataStore
}

//GetConfigFiles returns all Configuration Files in tenant service that have the given service path. The service path
//is a "/" delimited string of the service name hierarchy, i.e /Zenoss.Core/Zproxy
func (s *storeImpl) GetConfigFiles(ctx datastore.Context, tenantID string, svcPath string) ([]*SvcConfigFile, error) {
	defer ctx.Metrics().Stop(ctx.Metrics().Start(fmt.Sprintf("GetConfigFiles: svcPath=%s", svcPath)))
	search := search.Search("controlplane").Type(kind).Filter(
		"and",
		search.Filter().Terms("ServiceTenantID", tenantID),
		search.Filter().Terms("ServicePath", svcPath),
	)

	q := datastore.NewQuery(ctx)
	results, err := q.Execute(search)
	if err != nil {
		return nil, err
	}
	return convert(results)
}

func (s *storeImpl) GetConfigFile(ctx datastore.Context, tenantID, svcPath, filename string) (*SvcConfigFile, error) {
	search := search.Search("controlplane").Type(kind).Filter(
		"and",
		search.Filter().Terms("ServiceTenantID", tenantID),
		search.Filter().Terms("ServicePath", svcPath),
		search.Filter().Terms("ConfFile.Filename", filename),
	)

	q := datastore.NewQuery(ctx)
	results, err := q.Execute(search)
	if err != nil {
		return nil, err
	}

	if results.Len() > 0 {
		matches, err := convert(results)
		if err != nil {
			return nil, err
		}
		return matches[0], nil
	}

	return nil, nil
}

func convert(results datastore.Results) ([]*SvcConfigFile, error) {
	result := make([]*SvcConfigFile, results.Len())
	for idx := range result {
		var cf SvcConfigFile
		err := results.Get(idx, &cf)
		if err != nil {
			return nil, err
		}
		result[idx] = &cf
	}
	return result, nil
}

//Key creates a Key suitable for getting, putting and deleting SvcConfigFile
func Key(id string) datastore.Key {
	return datastore.NewKey(kind, id)
}

var (
	kind = "svcconfigfile"
)
