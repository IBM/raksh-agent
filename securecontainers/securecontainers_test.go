//
// Copyright (c) 2019 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

package securecontainers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestReadOciImageConfigJSON(t *testing.T) {

	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Errorf("Error creating directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	containerID := "123456"
	kataGuestSvmDir = tempDir
	configJSON := `{"ociVersion":"1.0.0","process":{"terminal":true,"user":{"uid":0,"gid":0},"args":["nginx","-g","daemon off;"],"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","NGINX_VERSION=1.17.5","NJS_VERSION=0.3.6","PKG_RELEASE=1~buster"],"cwd":"/"},"root":{"path":"rootfs"},"linux":{}}`
	testOciJSONSpec := &specs.Spec{}
	ociJSONSpec := &specs.Spec{}

	d1 := []byte(configJSON)
	configPathrootfs := filepath.Join(kataGuestSvmDir, containerID, "rootfs_bundle")
	err = os.MkdirAll(configPathrootfs, os.ModeDir)
	if err != nil {
		t.Errorf("Error creating directory: %v", err)
	}

	configPath := filepath.Join(kataGuestSvmDir, containerID, "rootfs_bundle", "config.json")
	err = ioutil.WriteFile(configPath, d1, 0644)
	if err != nil {
		t.Errorf("Failed to write oci image config json")
	}

	ociJSONSpec, err = readOciImageConfigJSON(containerID)
	if err != nil {
		t.Errorf("Failed to read oci image config json")
	}

	json.Unmarshal(d1, &testOciJSONSpec)
	if !reflect.DeepEqual(ociJSONSpec, testOciJSONSpec) {
		t.Errorf("Failed to correctly read oci image config json")
	}
}

func TestPersistDecryptedCM(t *testing.T) {

	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Errorf("Error creating directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	kataGuestSvmDir = tempDir
	containerID := "123456"
	decryptedConfig := `spec:
  containers:
  - env:
    - name: DEMO_GREETING
      value: Hello from the environment
    - name: DEMO_FAREWELL
      value: Such a sweet sorrow
    image: nginx:latest
    name: nginx
    ports:
    - containerPort: 80
    resources: {}`
	decryptedConfigByte := []byte(decryptedConfig)
	err = persistDecryptedCM(containerID, decryptedConfigByte)
	if err != nil {
		t.Errorf("Error creating directory: %v", err)
	}
	decryptFile := filepath.Join(kataGuestSvmDir, containerID, "decryptedConfig")
	dat, err := ioutil.ReadFile(decryptFile)
	if err != nil {
		t.Errorf("Failed reading config map")
	}

	res := bytes.Compare(decryptedConfigByte, dat)
	if res != 0 {
		t.Errorf("The configMap that was persisted and then read is not equal")
	}
}

func TestPullOciImage(t *testing.T) {

	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Errorf("Error creating directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	kataGuestSvmDir = tempDir
	containerID := "123456"
	image := "nginx"
	createDir := filepath.Join(kataGuestSvmDir, containerID, "rootfs_dir")
	destRefString := skopeoDestImageTransport + createDir

	err = testSkopeoCopy(image, containerID)
	if err != nil {
		t.Errorf("Error exeuting skopeo copy to pull oci image: %v", err)
	}

	// Three files should get created: blobs, index.json, oci-layout
	files, err := ioutil.ReadDir(createDir)
	if err != nil {
		t.Errorf("Failed reading directory %s", createDir)
	}

	if len(files) != 3 {
		t.Errorf("Skopeo copy failed copying oci images to %s", destRefString)
	}
}

func TestIsPauseContainer(t *testing.T) {
	args := []string{"pause", "nginx"}
	check := IsPauseContainer(args)
	if check {
		t.Errorf("Failed to identify a pause container")
	}
}

func testSkopeoCopy(image string, containerID string) error {

	_, err := exec.LookPath("skopeo")
	if err != nil {
		return errors.New("Skipping test as skopeo binary not present")
	}

	err = pullOciImage(image, containerID)
	return err

}

func TestCreateRuntimeBundle(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Errorf("Error creating directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	kataGuestSvmDir = tempDir
	containerID := "123456"
	image := "nginx"
	ociBundle := filepath.Join(kataGuestSvmDir, containerID, "rootfs_bundle")
	err = testSkopeoCopy(image, containerID)
	if err != nil {
		t.Errorf("Error exeuting skopeo copy to pull oci image: %v", err)
	}

	err = createRuntimeBundle(containerID)
	if err != nil {
		t.Errorf("Error creating runtime bundle: %v", err)
	}

	files, err := ioutil.ReadDir(ociBundle)
	if err != nil {
		t.Errorf("Failed reading directory %s", ociBundle)
	}

	//Two files should get created: config.json,  rootfs
	if len(files) != 2 {
		t.Errorf("Failed to create runtime bundle at %s", ociBundle)
	}
}

func TestFailRuntimeBundleCreation(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Errorf("Error creating directory: %v", err)
	}

	kataGuestSvmDir = tempDir
	containerID := "123456"
	image := "nginx"
	err = testSkopeoCopy(image, containerID)
	if err != nil {
		t.Errorf("Error exeuting skopeo copy to pull oci image: %v", err)
	}
	os.RemoveAll(tempDir)
	err = createRuntimeBundle(containerID)
	if err == nil {
		t.Errorf("Creating runtime bundle should have errored out")
	}
}
