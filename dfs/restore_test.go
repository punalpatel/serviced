// Copyright 2015 The Serviced Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build unit

package dfs_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"path"
	"time"

	. "github.com/control-center/serviced/dfs"
	"github.com/control-center/serviced/domain/pool"
	"github.com/control-center/serviced/domain/servicetemplate"
	"github.com/control-center/serviced/volume"
	volumemocks "github.com/control-center/serviced/volume/mocks"
	dockerclient "github.com/fsouza/go-dockerclient"
	"github.com/stretchr/testify/mock"
	. "gopkg.in/check.v1"
)

func (s *DFSTestSuite) TestRestore_LoadImages(c *C) {
	buf := bytes.NewBufferString("")
	tarfile := tar.NewWriter(buf)
	backupInfo := BackupInfo{
		Templates: []servicetemplate.ServiceTemplate{
			{ID: "test-template-1"},
		},
		BaseImages: []string{"library/repo:tag"},
		Pools: []pool.ResourcePool{
			{ID: "test-pool-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		Snapshots: []string{"BASE_LABEL"},
		Timestamp: time.Now().UTC(),
	}
	s.writeBackupInfo(c, tarfile, backupInfo)
	err := tarfile.WriteHeader(&tar.Header{Name: DockerImagesFile, Size: 0})
	c.Assert(err, IsNil)
	tarfile.Close()
	s.docker.On("LoadImage", mock.AnythingOfType("*tar.Reader")).Return(nil)
	err = s.dfs.Restore(buf, backupInfo.BackupVersion)
	c.Assert(err, IsNil)
	s.docker.AssertExpectations(c)
}

func (s *DFSTestSuite) TestRestore_ImportSnapshot(c *C) {
	buf := bytes.NewBufferString("")
	tarfile := tar.NewWriter(buf)
	backupInfo := BackupInfo{
		Templates: []servicetemplate.ServiceTemplate{
			{ID: "test-template-1"},
		},
		BaseImages: []string{},
		Pools: []pool.ResourcePool{
			{ID: "test-pool-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		Snapshots: []string{"BASE_LABEL"},
		Timestamp: time.Now().UTC(),
	}
	s.writeBackupInfo(c, tarfile, backupInfo)
	err := tarfile.WriteHeader(&tar.Header{Name: path.Join(SnapshotsMetadataDir, "BASE", "LABEL"), Size: 0})
	c.Assert(err, IsNil)
	tarfile.Close()
	s.disk.On("Create", "BASE").Return(&volumemocks.Volume{}, volume.ErrVolumeExists)
	vol := &volumemocks.Volume{}
	s.disk.On("Get", "BASE").Return(vol, nil)
	vol.On("Import", "LABEL", mock.AnythingOfType("*tar.Reader")).Return(nil)
	imgbuffer := bytes.NewBufferString("")
	err = json.NewEncoder(imgbuffer).Encode([]string{})
	c.Assert(err, IsNil)
	vol.On("ReadMetadata", "LABEL", ImagesMetadataFile).Return(&NopCloser{imgbuffer}, nil)
	err = s.dfs.Restore(buf, backupInfo.BackupVersion)
	c.Assert(err, IsNil)
	s.disk.AssertExpectations(c)
	vol.AssertExpectations(c)
}

func (s *DFSTestSuite) TestRestore_ImportSnapshotNoImagesCreate(c *C) {
	buf := bytes.NewBufferString("")
	tarfile := tar.NewWriter(buf)
	backupInfo := BackupInfo{
		Templates: []servicetemplate.ServiceTemplate{
			{ID: "test-template-1"},
		},
		BaseImages: []string{"some/image:now"},
		Pools: []pool.ResourcePool{
			{ID: "test-pool-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		Snapshots: []string{"BASE_LABEL"},
		Timestamp: time.Now().UTC(),
	}
	s.writeBackupInfo(c, tarfile, backupInfo)
	err := tarfile.WriteHeader(&tar.Header{Name: path.Join(SnapshotsMetadataDir, "BASE", "LABEL"), Size: 0})
	c.Assert(err, IsNil)
	tarfile.Close()
	vol := &volumemocks.Volume{}
	s.disk.On("Create", "BASE").Return(vol, nil)
	s.disk.On("Get", "BASE").Return(vol, nil)
	vol.On("Import", "LABEL", mock.AnythingOfType("*tar.Reader")).Return(nil)
	vol.On("ReadMetadata", "LABEL", ImagesMetadataFile).Return(&NopCloser{}, ErrTestNoImagesMetadata)
	vol.On("RemoveSnapshot", "LABEL").Return(nil)
	//s.disk.On("Remove", "BASE").Return(nil)
	err = s.dfs.Restore(buf, backupInfo.BackupVersion)
	c.Assert(err, Equals, ErrTestNoImagesMetadata)
	s.disk.AssertExpectations(c)
	vol.AssertExpectations(c)
}

func (s *DFSTestSuite) TestRestore_ImportSnapshotNoImagesGet(c *C) {
	buf := bytes.NewBufferString("")
	tarfile := tar.NewWriter(buf)
	backupInfo := BackupInfo{
		Templates: []servicetemplate.ServiceTemplate{
			{ID: "test-template-1"},
		},
		BaseImages: []string{"some/image:now"},
		Pools: []pool.ResourcePool{
			{ID: "test-pool-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		Snapshots: []string{"BASE_LABEL"},
		Timestamp: time.Now().UTC(),
	}
	s.writeBackupInfo(c, tarfile, backupInfo)
	err := tarfile.WriteHeader(&tar.Header{Name: path.Join(SnapshotsMetadataDir, "BASE", "LABEL"), Size: 0})
	c.Assert(err, IsNil)
	tarfile.Close()
	vol := &volumemocks.Volume{}
	s.disk.On("Create", "BASE").Return(&volumemocks.Volume{}, volume.ErrVolumeExists)
	s.disk.On("Get", "BASE").Return(vol, nil)
	vol.On("Import", "LABEL", mock.AnythingOfType("*tar.Reader")).Return(nil)
	vol.On("ReadMetadata", "LABEL", ImagesMetadataFile).Return(&NopCloser{}, ErrTestNoImagesMetadata)
	vol.On("RemoveSnapshot", "LABEL").Return(nil)
	err = s.dfs.Restore(buf, backupInfo.BackupVersion)
	c.Assert(err, Equals, ErrTestNoImagesMetadata)
	s.disk.AssertExpectations(c)
	vol.AssertExpectations(c)
}
func (s *DFSTestSuite) TestRestore_ImportSnapshotImageNotFound(c *C) {
	buf := bytes.NewBufferString("")
	tarfile := tar.NewWriter(buf)
	backupInfo := BackupInfo{
		Templates: []servicetemplate.ServiceTemplate{
			{ID: "test-template-1"},
		},
		BaseImages: []string{"some/image:now"},
		Pools: []pool.ResourcePool{
			{ID: "test-pool-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		Snapshots: []string{"BASE_LABEL"},
		Timestamp: time.Now().UTC(),
	}
	s.writeBackupInfo(c, tarfile, backupInfo)
	err := tarfile.WriteHeader(&tar.Header{Name: path.Join(SnapshotsMetadataDir, "BASE", "LABEL"), Size: 0})
	c.Assert(err, IsNil)
	tarfile.Close()
	vol := &volumemocks.Volume{}
	s.disk.On("Create", "BASE").Return(vol, nil)
	s.disk.On("Get", "BASE").Return(vol, nil)
	vol.On("Import", "LABEL", mock.AnythingOfType("*tar.Reader")).Return(nil)
	imgbuffer := bytes.NewBufferString("")
	err = json.NewEncoder(imgbuffer).Encode([]string{"test:5000/image:now"})
	c.Assert(err, IsNil)
	vol.On("ReadMetadata", "LABEL", ImagesMetadataFile).Return(&NopCloser{imgbuffer}, nil)
	s.docker.On("FindImage", "test:5000/image:now").Return(&dockerclient.Image{}, ErrTestImageNotFound)
	err = s.dfs.Restore(buf, backupInfo.BackupVersion)
	c.Assert(err, IsNil) // Image not found, so log a warning
	s.disk.AssertExpectations(c)
	vol.AssertExpectations(c)
}

func (s *DFSTestSuite) TestRestore_ImportSnapshotImageNoPush(c *C) {
	buf := bytes.NewBufferString("")
	tarfile := tar.NewWriter(buf)
	backupInfo := BackupInfo{
		Templates: []servicetemplate.ServiceTemplate{
			{ID: "test-template-1"},
		},
		BaseImages: []string{"some/image:now"},
		Pools: []pool.ResourcePool{
			{ID: "test-pool-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		Snapshots: []string{"BASE_LABEL"},
		Timestamp: time.Now().UTC(),
	}
	s.writeBackupInfo(c, tarfile, backupInfo)
	err := tarfile.WriteHeader(&tar.Header{Name: path.Join(SnapshotsMetadataDir, "BASE", "LABEL"), Size: 0})
	c.Assert(err, IsNil)
	tarfile.Close()
	vol := &volumemocks.Volume{}
	s.disk.On("Create", "BASE").Return(vol, nil)
	s.disk.On("Get", "BASE").Return(vol, nil)
	vol.On("Import", "LABEL", mock.AnythingOfType("*tar.Reader")).Return(nil)
	imgbuffer := bytes.NewBufferString("")
	err = json.NewEncoder(imgbuffer).Encode([]string{"test:5000/image:now"})
	c.Assert(err, IsNil)
	vol.On("ReadMetadata", "LABEL", ImagesMetadataFile).Return(&NopCloser{imgbuffer}, nil)
	s.docker.On("FindImage", "test:5000/image:now").Return(&dockerclient.Image{ID: "someimageid"}, nil)
	s.docker.On("GetImageHash", "someimageid").Return("hashvalue", nil)
	s.index.On("PushImage", "test:5000/image:now", "someimageid", "hashvalue").Return(ErrTestNoPush)
	err = s.dfs.Restore(buf, backupInfo.BackupVersion)
	c.Assert(err, Equals, ErrTestNoPush)
	s.disk.AssertExpectations(c)
	vol.AssertExpectations(c)
}

func (s *DFSTestSuite) TestRestore_ImportSnapshotImageNoHash(c *C) {
	buf := bytes.NewBufferString("")
	tarfile := tar.NewWriter(buf)
	backupInfo := BackupInfo{
		Templates: []servicetemplate.ServiceTemplate{
			{ID: "test-template-1"},
		},
		BaseImages: []string{"some/image:now"},
		Pools: []pool.ResourcePool{
			{ID: "test-pool-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		Snapshots: []string{"BASE_LABEL"},
		Timestamp: time.Now().UTC(),
	}
	s.writeBackupInfo(c, tarfile, backupInfo)
	err := tarfile.WriteHeader(&tar.Header{Name: path.Join(SnapshotsMetadataDir, "BASE", "LABEL"), Size: 0})
	c.Assert(err, IsNil)
	tarfile.Close()
	vol := &volumemocks.Volume{}
	s.disk.On("Create", "BASE").Return(vol, nil)
	s.disk.On("Get", "BASE").Return(vol, nil)
	vol.On("Import", "LABEL", mock.AnythingOfType("*tar.Reader")).Return(nil)
	imgbuffer := bytes.NewBufferString("")
	err = json.NewEncoder(imgbuffer).Encode([]string{"test:5000/image:now"})
	c.Assert(err, IsNil)
	vol.On("ReadMetadata", "LABEL", ImagesMetadataFile).Return(&NopCloser{imgbuffer}, nil)
	s.docker.On("FindImage", "test:5000/image:now").Return(&dockerclient.Image{ID: "someimageid"}, nil)
	s.docker.On("GetImageHash", "someimageid").Return("", ErrTestNoHash)
	err = s.dfs.Restore(buf, backupInfo.BackupVersion)
	c.Assert(err, Equals, ErrTestNoHash)
	s.disk.AssertExpectations(c)
	vol.AssertExpectations(c)
}

func (s *DFSTestSuite) TestRestore_ImportSnapshotSnapshotExists(c *C) {
	buf := bytes.NewBufferString("")
	tarfile := tar.NewWriter(buf)
	backupInfo := BackupInfo{
		Templates: []servicetemplate.ServiceTemplate{
			{ID: "test-template-1"},
		},
		BaseImages: []string{},
		Pools: []pool.ResourcePool{
			{ID: "test-pool-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		Snapshots:     []string{"BASE_LABEL"},
		Timestamp:     time.Now().UTC(),
		BackupVersion: 1,
	}
	s.writeBackupInfo(c, tarfile, backupInfo)
	err := tarfile.WriteHeader(&tar.Header{Name: path.Join(SnapshotsMetadataDir, "BASE", "LABEL"), Size: 0})
	c.Assert(err, IsNil)
	tarfile.Close()
	vol := &volumemocks.Volume{}
	// s.disk.On("Exists", "BASE_LABEL").Return(true)
	s.docker.On("LoadImage", mock.AnythingOfType("*io.PipeReader")).Return(nil).Run(func(a mock.Arguments) {
		reader := a.Get(0).(io.Reader)
		io.Copy(ioutil.Discard, reader)
	})
	imgbuffer := bytes.NewBufferString("")
	err = json.NewEncoder(imgbuffer).Encode([]string{})
	c.Assert(err, IsNil)
	err = s.dfs.Restore(buf, backupInfo.BackupVersion)
	c.Assert(err, IsNil)
	s.disk.AssertExpectations(c)
	vol.AssertExpectations(c)
}

func (s *DFSTestSuite) TestRestore_ImportSnapshotBadSnapshot(c *C) {
	vol := &volumemocks.Volume{}
	s.disk.On("Create", "BASE").Return(vol, nil)
	s.disk.On("Remove", "BASE").Return(nil)

	binfo := BackupInfo{
		Templates: []servicetemplate.ServiceTemplate{
			{ID: "test-template-1"},
		},
		BaseImages: []string{},
		Pools: []pool.ResourcePool{
			{ID: "test-pool-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		Snapshots:     []string{"BASE_LABEL"},
		Timestamp:     time.Now().UTC(),
		BackupVersion: 1,
	}

	// bad snapshot
	vol.On("Import", "LABEL", mock.AnythingOfType("*io.PipeReader")).Run(func(a mock.Arguments) {
		r := a.Get(1).(io.Reader)
		tr := tar.NewReader(r)
		hdr, err := tr.Next()
		c.Assert(err, IsNil)
		c.Assert(hdr.Name, Equals, "dummy")
		hdr, err = tr.Next()
		c.Assert(err, Equals, ErrTestBadSnapshot)
		c.Assert(hdr, IsNil)
	}).Return(ErrTestBadSnapshot).Once()

	w, errc := s.setupRestorePipe(binfo.BackupVersion)
	tw := tar.NewWriter(w)
	s.writeBackupInfo(c, tw, binfo)
	err := tw.WriteHeader(&tar.Header{
		Name: path.Join(SnapshotsMetadataDir, "BASE", "LABEL", "dummy"),
		Size: 0,
	})
	c.Assert(err, IsNil)
	tw.Flush()
	w.CloseWithError(ErrTestBadSnapshot)
	c.Assert(<-errc, Equals, ErrTestBadSnapshot)

	// good snapshot
	s.disk.On("Get", "BASE").Return(vol, nil)
	imgbuffer := bytes.NewBufferString("")
	err = json.NewEncoder(imgbuffer).Encode([]string{})
	c.Assert(err, IsNil)
	vol.On("ReadMetadata", "LABEL", ImagesMetadataFile).Return(&NopCloser{imgbuffer}, nil)

	vol.On("Import", "LABEL", mock.AnythingOfType("*io.PipeReader")).Run(func(a mock.Arguments) {
		r := a.Get(1).(io.Reader)
		tr := tar.NewReader(r)
		hdr, err := tr.Next()
		c.Assert(err, IsNil)
		c.Assert(hdr.Name, Equals, "dummy")
		hdr, err = tr.Next()
		c.Assert(err, Equals, io.EOF)
		c.Assert(hdr, IsNil)
	}).Return(nil).Once()

	w, errc = s.setupRestorePipe(binfo.BackupVersion)
	tw = tar.NewWriter(w)
	s.writeBackupInfo(c, tw, binfo)
	err = tw.WriteHeader(&tar.Header{
		Name: path.Join(SnapshotsMetadataDir, "BASE", "LABEL", "dummy"),
		Size: 0,
	})
	c.Assert(err, IsNil)
	tw.Close()
	w.Close()
	c.Assert(<-errc, IsNil)

}

func (s *DFSTestSuite) setupRestorePipe(version int) (*io.PipeWriter, <-chan error) {
	r, w := io.Pipe()
	errc := make(chan error)
	go func() {
		errc <- s.dfs.Restore(r, version)
	}()
	return w, errc
}

func (s *DFSTestSuite) TestRestore_ImportSnapshot_FailGettingVolume(c *C) {
	ErrNoVolume := errors.New("error getting volume")

	buf := bytes.NewBufferString("")
	tarfile := tar.NewWriter(buf)
	backupInfo := BackupInfo{
		Templates: []servicetemplate.ServiceTemplate{
			{ID: "test-template-1"},
		},
		BaseImages: []string{},
		Pools: []pool.ResourcePool{
			{ID: "test-pool-1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()},
		},
		Snapshots: []string{"BASE_LABEL"},
		Timestamp: time.Now().UTC(),
	}
	s.writeBackupInfo(c, tarfile, backupInfo)
	err := tarfile.WriteHeader(&tar.Header{Name: path.Join(SnapshotsMetadataDir, "BASE", "LABEL"), Size: 0})
	c.Assert(err, IsNil)
	tarfile.Close()
	s.disk.On("Create", "BASE").Return(&volumemocks.Volume{}, volume.ErrVolumeExists)
	s.disk.On("Get", "BASE").Return(&volumemocks.Volume{}, ErrNoVolume)
	err = s.dfs.Restore(buf, backupInfo.BackupVersion)
	c.Assert(err, Equals, ErrNoVolume)
	s.disk.AssertExpectations(c)
}

func (s *DFSTestSuite) writeBackupInfo(c *C, tarfile *tar.Writer, backupInfo BackupInfo) {
	bytedata, err := json.Marshal(backupInfo)
	c.Assert(err, IsNil)
	err = tarfile.WriteHeader(&tar.Header{Name: BackupMetadataFile, Size: int64(len(bytedata))})
	c.Assert(err, IsNil)
	_, err = tarfile.Write(bytedata)
	c.Assert(err, IsNil)
}
