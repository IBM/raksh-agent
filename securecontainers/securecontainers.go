//
// Copyright (c) 2019 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

package securecontainers

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kata-containers/agent/crypto"
	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	agentName                  = "kata-agent"
	configmapFileName          = "raksh.properties"
	configmapJSONFileName      = "config.json"
	rootfsBundleDir            = "rootfs_bundle"
	kataGuestSharedDir         = "/run/kata-containers/shared/containers"
	skopeoSrcImageTransport    = "docker://" //Todo: Handle other registries as well
	skopeoDestImageTransport   = "oci:"
	configmapMountPoint        = "/etc/raksh"
	rakshSecretDefMountPoint   = "/etc/raksh-secrets"
	rakshSecretVMTEEMountPoint = "/run/raksh-secrets"
	configMapKeyFileName       = "configMapKey"
	imageKeyFileName           = "imageKey"
	nonceFileName              = "nonce"
)

var agentFields = logrus.Fields{
	"name":   agentName,
	"pid":    os.Getpid(),
	"source": "agent",
}

var agentLog = logrus.WithFields(agentFields)
var kataGuestSvmDir = "/run/svm"

type svmConfig struct {
	Spec spec `yaml:"spec"`
}
type requests struct {
	CPU    string `yaml:"cpu"`
	Memory string `yaml:"memory"`
}
type resources struct {
	Requests requests `yaml:"requests"`
}
type env struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}
type ports struct {
	ContainerPort int `yaml:"containerPort"`
}
type containers struct {
	Name      string    `yaml:"name"`
	Image     string    `yaml:"image"`
	Resources resources `yaml:"resources"`
	Args      []string  `yaml:"args"`
	Env       []env     `yaml:"env"`
	Cwd       string    `yaml:"cwd"`
	Ports     []ports   `yaml:"ports"`
}
type spec struct {
	Containers []containers `yaml:"containers"`
}

//IsPauseContainer checks if it is pause container
func IsPauseContainer(args []string) bool {
	//TODO: Handle infra pod incase of openshift
	pauseArgs := "/pause"

	if len(args) == 1 && pauseArgs == args[0] {
		agentLog.Debug("It is a pause image")
		return true
	}
	return false
}

//UpdateSecureContainersOCIReq updates the OCI Request for a secure container from an encrypted configmap inside Kata VM
func UpdateSecureContainersOCIReq(ociSpec *specs.Spec, req *pb.CreateContainerRequest) error {

	svmConfig, err := readEncryptedConfigmap(req, ociSpec.Process.Env)
	if err != nil {
		agentLog.WithError(err).Errorf("readEncryptedConfigmap errored out: %s", err)
		return err
	}

	err = pullOciImage(svmConfig.Spec.Containers[0].Image, req.ContainerId)
	if err != nil {
		agentLog.WithError(err).Errorf("pullSecureImage errored out: %s", err)
		return err
	}

	err = createRuntimeBundle(req.ContainerId)
	if err != nil {
		agentLog.WithError(err).Errorf("createRuntimeBundle errored out: %s", err)
		return err
	}

	err = updateOCIReq(req, *svmConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("updating OCI Request errored out: %s", err)
		return err
	}

	ociSpec.Root.Path = filepath.Join(kataGuestSvmDir, req.ContainerId, rootfsBundleDir, "rootfs")

	return nil
}

//Read encrypted configmap volume mounted into the scratch image.
func readEncryptedConfigmap(req *pb.CreateContainerRequest, containerEnv []string) (*svmConfig, error) {

	var svmConfig svmConfig
	var file string

	agentLog.Debug("containerEnv: ", containerEnv)
	agentLog.Debug("Reading encrypted configmap for container:", req.ContainerId)
	for _, mounts := range req.OCI.Mounts {
		if mounts.Destination == configmapMountPoint {
			file = filepath.Join(mounts.Source, configmapFileName)
			agentLog.Debug("Found encrypted configmap at:", mounts.Source)
			break
		}
	}

	if len(file) == 0 {
		err := errors.New("No encrypted configmap found")
		agentLog.WithError(err).Errorf("Error finding configmap")
		return nil, err
	}

	err := fileExists(file)
	if err != nil {
		agentLog.WithError(err).Errorf("Error looking for %s", file)
		return nil, err
	}

	agentLog.WithField("ConfigMap path: ", file).Debug("Found file for reading config map")
	encryptedYamlContainerSpec, err := ioutil.ReadFile(file)
	if err != nil {
		agentLog.WithError(err).Errorf("Could not read file %s: %s", file, err)
		return nil, err
	}

	containerspec, err := b64.StdEncoding.DecodeString(string(encryptedYamlContainerSpec)) //decoded into an encoded blob
	if err != nil {
		return nil, err
	}

	//Ignore imgKey for now
	configmapKey, _, nonce, err := readSecrets(req)
	if err != nil {
		return nil, err
	}

	decryptedConfig, err := crypto.DecryptSVMConfig(containerspec, configmapKey, nonce)
	if err != nil {
		return nil, err
	}

	err = persistDecryptedCM(req.ContainerId, decryptedConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error when persisting decrypted configmap %s", err)
		return nil, err
	}

	err = yaml.Unmarshal(decryptedConfig, &svmConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error unmarshalling yaml %s", err)
		return nil, err
	}

	return &svmConfig, err

}

//Read secrets mounted into well-defined path
func readSecrets(req *pb.CreateContainerRequest) (configMapKey []byte, imageKey []byte, nonce []byte, err error) {

	var configMapKeyFile, nonceFile, imageKeyFile string

	agentLog.Debug("Reading secrets for container: ", req.ContainerId)

	if crypto.IsVMTEE() == true {
		//VM TEE
		err = crypto.PopulateSecretsForVMTEE()
		if err != nil {
			agentLog.WithError(err).Errorf("Error populating secrets for TEE")
			return nil, nil, nil, err
		}
		configMapKeyFile = filepath.Join(rakshSecretVMTEEMountPoint, configMapKeyFileName)
		imageKeyFile = filepath.Join(rakshSecretVMTEEMountPoint, imageKeyFileName)
		nonceFile = filepath.Join(rakshSecretVMTEEMountPoint, nonceFileName)
		agentLog.Debug("Found secrets at: ", rakshSecretVMTEEMountPoint)
	} else {
		//non VM TEE case
		for _, mounts := range req.OCI.Mounts {
			if mounts.Destination == rakshSecretDefMountPoint {
				configMapKeyFile = filepath.Join(mounts.Source, configMapKeyFileName)
				nonceFile = filepath.Join(mounts.Source, nonceFileName)
				imageKeyFile = filepath.Join(mounts.Source, imageKeyFileName)
				agentLog.Debug("Found secrets at: ", mounts.Destination)
				break
			}
		}
	}

	configMapKey, err = readSecretFile(configMapKeyFile)
	if err != nil {
		return nil, nil, nil, err
	}

	imageKey, err = readSecretFile(imageKeyFile)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce, err = readSecretFile(nonceFile)
	if err != nil {
		return nil, nil, nil, err
	}

	return configMapKey, imageKey, nonce, nil
}

//Get the secrets from the relevant files
func readSecretFile(fileName string) ([]byte, error) {

	err := fileExists(fileName)
	if err != nil {
		agentLog.WithError(err).Errorf("Error looking for %s", fileName)
		return nil, err
	}

	//The secrets are base64 encoded
	keyEnc, err := ioutil.ReadFile(fileName)
	if err != nil {
		agentLog.WithError(err).Errorf("Could not read file %s: %s", fileName, err)
		return nil, err
	}

	keyDecoded, err := b64.StdEncoding.DecodeString(string(keyEnc))
	return keyDecoded, err
}

func createOCIRuntimeBundle(ociImage string, ociBundle string) error {

	agentLog.Debug("Executing oci-image-tool to create OCI runtime bundle")
	args := []string{"create", "--ref=platform.os=linux", ociImage, ociBundle}
	execResult, err := execCommand("oci-image-tool", args)
	agentLog.WithField("oci-image-tool exec result: ", execResult).Debug("create oci bundle")
	if err != nil {
		return err
	}

	err = fileExists(ociBundle)
	if err != nil {
		agentLog.WithError(err).Errorf("Error looking for ociBundle: %s", ociBundle)
	}

	return err
}

func makeOCIBundleExecutable(ociBundle string) error {

	agentLog.Debug("Executing chmod to make ociBundle executable")
	args := []string{"-R", "+x", ociBundle}
	execResult, err := execCommand("chmod", args)
	agentLog.WithField("chmod exec result: ", execResult).Debug("making ociBundle executable")
	return err
}

func createRuntimeBundle(containerID string) error {

	ociBundle := filepath.Join(kataGuestSvmDir, containerID, rootfsBundleDir)
	ociImage := filepath.Join(kataGuestSvmDir, containerID, "rootfs_dir")

	agentLog.WithField("rootfs_dir is: ", ociImage).Debug("Path to ociImage")
	agentLog.WithField("rootfs_bundle is: ", ociBundle).Debug("Path to ociBundle")
	agentLog.Debug("Create runtime bundle for container id:", containerID)

	// Since image.CreateRuntimeBundleLayout is returning a nil pointer exception, os exec the oci-image-tool directly
	err := createOCIRuntimeBundle(ociImage, ociBundle)
	if err != nil {
		return err
	}
	agentLog.WithField("ociBundle: ", ociBundle).Debug("Created ociBundle successfully")

	// Make ociBundle executable as some images need to execute .sh files at startup
	err = makeOCIBundleExecutable(ociBundle)
	if err != nil {
		return err
	}
	agentLog.WithField("ociBundle: ", ociBundle).Debug("Made ociBundle executable")
	return err
}

func persistDecryptedCM(containerID string, decryptedConfig []byte) error {

	decryptCMDir := filepath.Join(kataGuestSvmDir, containerID)
	decryptCMFile := filepath.Join(decryptCMDir, "decryptedConfig")

	agentLog.Debug("Create directory to write decrypted configmap into: ", decryptCMDir)
	err := os.MkdirAll(decryptCMDir, os.ModeDir)
	if err != nil {
		return err
	}

	agentLog.Debug("Write decrypted configmap into: ", decryptCMFile)
	err = ioutil.WriteFile(decryptCMFile, decryptedConfig, 0644)
	return err
}

func execCommand(binary string, args []string) (string, error) {

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(binary, args...)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	execResult := "Output: " + out.String() + " Error: " + stderr.String()
	return execResult, err
}

func pullOciImage(image string, containerID string) error {

	pull := skopeoSrcImageTransport + image
	createDir := filepath.Join(kataGuestSvmDir, containerID, "rootfs_dir:latest")
	destRefString := skopeoDestImageTransport + createDir

	err := os.MkdirAll(createDir, os.ModeDir)
	if err != nil {
		agentLog.WithError(err).Errorf("Error creating directory %s %s", createDir, err)
		return err
	}

	//ToDo: Add skopeo copy with authorization and via API.
	agentLog.Debug("Executing skopeo copy for containerID ", containerID)
	args := []string{"copy", pull, destRefString}
	execResult, err := execCommand("skopeo", args)
	agentLog.WithField("skopeo copy exec result: ", execResult).Debug("Copy image using skopeo")

	return err
}

//UpdateExecProcessConfig updates the Exec process env and cwd attributes
func UpdateExecProcessConfig(containerID string, processEnv []string, processCwd string) ([]string, string, error) {

	var svmConfig svmConfig
	decryptedConfig := filepath.Join(kataGuestSvmDir, containerID, "decryptedConfig")
	data, err := ioutil.ReadFile(decryptedConfig)
	err = yaml.Unmarshal(data, &svmConfig)
	if err != nil {
		agentLog.WithError(err).Errorf("Error unmarshalling yaml while execing inside container %s", err)
		return processEnv, processCwd, err
	}

	ociJSONSpec, err := readOciImageConfigJSON(containerID)
	if err != nil {
		agentLog.WithError(err).Errorf("readConfigJSON errored out: %s", err)
		return processEnv, processCwd, err
	}

	if len(svmConfig.Spec.Containers[0].Env) != 0 {
		processEnv = updateEnv(processEnv, ociJSONSpec.Process.Env, svmConfig)
	}

	processCwd = updateCwd(processCwd, ociJSONSpec.Process.Cwd, svmConfig.Spec.Containers[0].Cwd, svmConfig)
	return processEnv, processCwd, nil
}

func fileExists(path string) error {

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return errors.New("File does not exist")
	} else if err != nil {
		return errors.New("File may or may not exist")
	}
	return nil
}

func readOciImageConfigJSON(containerID string) (*specs.Spec, error) {

	var ociJSONSpec = &specs.Spec{}
	configPath := filepath.Join(kataGuestSvmDir, containerID, rootfsBundleDir, configmapJSONFileName)
	agentLog.Debug("Reading configJSONBytes from", configPath)

	configJSONBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		agentLog.WithError(err).Errorf("Could not open OCI config file %s", configPath)
		return ociJSONSpec, err
	}

	agentLog.Debug("Unmarshalling the config json data from ", configPath)
	if err := json.Unmarshal(configJSONBytes, &ociJSONSpec); err != nil {
		agentLog.WithError(err).Errorf("Could not unmarshall OCI config file")
		return ociJSONSpec, err
	}

	return ociJSONSpec, nil
}

func updateEnv(ociEnv []string, ociJSONEnv []string, svmConfig svmConfig) []string {
	ociEnv = append(ociEnv, ociJSONEnv...)
	for i := 0; i < len(svmConfig.Spec.Containers[0].Env); i++ {
		createEnv := svmConfig.Spec.Containers[0].Env[i].Name + "=" + svmConfig.Spec.Containers[0].Env[i].Value
		ociEnv = append(ociEnv, createEnv)
	}
	return ociEnv
}

func updateCwd(ociCwd string, ociJSONCwd string, svmConfigCwd string, svmConfig svmConfig) string {
	if svmConfig.Spec.Containers[0].Cwd != "" {
		ociCwd = svmConfigCwd
	} else {
		ociCwd = ociJSONCwd
	}
	return ociCwd
}

func updateOCIReq(req *pb.CreateContainerRequest, svmConfig svmConfig) error {

	ociJSONSpec, err := readOciImageConfigJSON(req.ContainerId)
	if err != nil {
		agentLog.WithError(err).Errorf("readOciImageConfigJSON Errored out: %s", err)
		return err
	}

	// Give higher priority to args specified in the pod yaml in CM than json spec of the image
	if len(svmConfig.Spec.Containers[0].Args) == 0 {
		req.OCI.Process.Args = ociJSONSpec.Process.Args
	} else {
		req.OCI.Process.Args = svmConfig.Spec.Containers[0].Args
	}

	if len(svmConfig.Spec.Containers[0].Env) != 0 {
		req.OCI.Process.Env = updateEnv(req.OCI.Process.Env, ociJSONSpec.Process.Env, svmConfig)
	}

	req.OCI.Process.Cwd = updateCwd(req.OCI.Process.Cwd, ociJSONSpec.Process.Cwd, svmConfig.Spec.Containers[0].Cwd, svmConfig)
	return nil
}
