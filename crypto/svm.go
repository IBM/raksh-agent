package crypto

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//Key Functions
// isSVM - Check if SVM
// populateSecretsForSVM
// populateKeyFileforSVM - populates the required secrets in files

//Returns true if SVM/PEF
func isSVM() bool {
	svm, err := ioutil.ReadFile(svmFile)
	if err != nil {
		agentLog.Debug("Error reading svm file: ", svmFile, err)
	}

	if strings.Trim(string(svm), "\n") == "1" {
		agentLog.Debug("It is a VM with SVM/PEF support")
		return true
	}
	agentLog.Debug("It is not an SVM")
	return false
}

//Populate secrets by calling esmb-get-file which will retrieve the
//embedded secret using ultravisor
func populateSecretsForSVM() error {

	agentLog.Debug("Populating secrets for SVM/PEF")
	err := os.MkdirAll(rakshSecretsVMTEEDir, os.ModeDir)
	if err != nil {
		agentLog.Debug("Unable to create directory for storing SVM/PEF secrets")
		return err
	}
	configMapKeyFile := filepath.Join(rakshSecretsVMTEEDir, configMapKeyFileName)
	imageKeyFile := filepath.Join(rakshSecretsVMTEEDir, imageKeyFileName)
	nonceFile := filepath.Join(rakshSecretsVMTEEDir, nonceFileName)

	err = populateKeyFileforSVM(configMapKeyFile)
	if err != nil {
		return err
	}
	err = populateKeyFileforSVM(imageKeyFile)
	if err != nil {
		return err
	}
	err = populateKeyFileforSVM(nonceFile)
	if err != nil {
		return err
	}

	return nil
}

//Retrieve the secrets from SVM and write to the file
func populateKeyFileforSVM(fileName string) error {

	agentLog.Debug("Populate the Key Files for SVM/PEF")
	_, err := os.Stat(fileName)
	if err == nil {
		agentLog.Debug("Secrets File exists for: ", fileName)
		return nil
	}
	//Retrieve imageKey
	filePtr, err := os.Create(fileName)
	if err != nil {
		agentLog.Debug("Unable to create file - ", fileName)
		return err
	}
	defer filePtr.Close()
	err = retrieveSecretsFilefromUltravisor(fileName, filePtr)
	if err != nil {
		agentLog.Debug("Error executing esmb-get-file for   ", fileName, err)
		return err
	}
	return nil
}

//Retrieve secrets file from SVM - ultravisor
func retrieveSecretsFilefromUltravisor(fileName string, outFile *os.File) error {

	agentLog.Debug("Retrieve the secrets from Ultravisor")
	var stderr bytes.Buffer

	cmd := exec.Command("esmb-get-file", "-f", fileName)
	//Note: NewLine gets added to Stdout. Buffer has an extra \n char
	cmd.Stdout = outFile
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		agentLog.Debug("Error executing esmb-get-file for configMapKey ", err, stderr.String())
		return err
	}
	return nil
}
