/*
Copyright 2017 The Kubernetes Authors.

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

package openstack

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/backups"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/snapshots"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/spf13/pflag"
	gcfg "gopkg.in/gcfg.v1"
	"k8s.io/cloud-provider-openstack/pkg/client"
	"k8s.io/cloud-provider-openstack/pkg/metrics"
	"k8s.io/cloud-provider-openstack/pkg/util/metadata"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"
)

// userAgentData is used to add extra information to the gophercloud user-agent
var userAgentData []string

// AddExtraFlags is called by the main package to add component specific command line flags
func AddExtraFlags(fs *pflag.FlagSet) {
	fs.StringArrayVar(&userAgentData, "user-agent", nil, "Extra data to add to gophercloud user-agent. Use multiple times to add more than one component.")
}

type IOpenStack interface {
	CreateVolume(context.Context, *volumes.CreateOpts, volumes.SchedulerHintOptsBuilder) (*volumes.Volume, error)
	DeleteVolume(ctx context.Context, volumeID string) error
	AttachVolume(ctx context.Context, instanceID, volumeID string) (string, error)
	ListVolumes(ctx context.Context, limit int, startingToken string) ([]volumes.Volume, string, error)
	WaitDiskAttached(ctx context.Context, instanceID string, volumeID string) error
	DetachVolume(ctx context.Context, instanceID, volumeID string) error
	WaitDiskDetached(ctx context.Context, instanceID string, volumeID string) error
	WaitVolumeTargetStatus(ctx context.Context, volumeID string, tStatus []string) error
	GetAttachmentDiskPath(ctx context.Context, instanceID, volumeID string) (string, error)
	GetVolume(ctx context.Context, volumeID string) (*volumes.Volume, error)
	GetVolumesByName(ctx context.Context, name string) ([]volumes.Volume, error)
	GetVolumeByName(ctx context.Context, name string) (*volumes.Volume, error)
	CreateSnapshot(ctx context.Context, name, volID string, tags map[string]string) (*snapshots.Snapshot, error)
	ListSnapshots(ctx context.Context, filters map[string]string) ([]snapshots.Snapshot, string, error)
	DeleteSnapshot(ctx context.Context, snapID string) error
	GetSnapshotByID(ctx context.Context, snapshotID string) (*snapshots.Snapshot, error)
	WaitSnapshotReady(ctx context.Context, snapshotID string) (string, error)
	CreateBackup(ctx context.Context, name, volID, snapshotID, availabilityZone string, tags map[string]string) (*backups.Backup, error)
	ListBackups(ctx context.Context, filters map[string]string) ([]backups.Backup, error)
	DeleteBackup(ctx context.Context, backupID string) error
	GetBackupByID(ctx context.Context, backupID string) (*backups.Backup, error)
	BackupsAreEnabled() (bool, error)
	WaitBackupReady(ctx context.Context, backupID string, snapshotSize int, backupMaxDurationSecondsPerGB int) (string, error)
	GetInstanceByID(ctx context.Context, instanceID string) (*servers.Server, error)
	ExpandVolume(ctx context.Context, volumeID string, status string, size int) error
	GetMaxVolLimit() int64
	GetMetadataOpts() metadata.Opts
	GetBlockStorageOpts() BlockStorageOpts
	ResolveVolumeListToUUIDs(ctx context.Context, volumes string) (string, error)
}

type OpenStack struct {
	compute      *gophercloud.ServiceClient
	blockstorage *gophercloud.ServiceClient
	bsOpts       BlockStorageOpts
	epOpts       gophercloud.EndpointOpts
	metadataOpts metadata.Opts
}

type BlockStorageOpts struct {
	NodeVolumeAttachLimit    int64 `gcfg:"node-volume-attach-limit"`
	RescanOnResize           bool  `gcfg:"rescan-on-resize"`
	IgnoreVolumeAZ           bool  `gcfg:"ignore-volume-az"`
	IgnoreVolumeMicroversion bool  `gcfg:"ignore-volume-microversion"`
}

type Config struct {
	Global       map[string]*client.AuthOpts
	Metadata     metadata.Opts
	BlockStorage BlockStorageOpts
}

func logcfg(cfg Config) {
	for cloudName, global := range cfg.Global {
		klog.V(0).Infof("Global: \"%s\"", cloudName)
		client.LogCfg(*global)
	}
	klog.Infof("Block storage opts: %v", cfg.BlockStorage)
}

// Loại bỏ padding kiểu PKCS7
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data emtry")
	}
	padLen := int(data[length-1])
	if padLen > length {
		return nil, fmt.Errorf("padding error")
	}
	return data[:(length - padLen)], nil
}

// Giải mã AES-ECB
func DecryptECB(cipherTextBase64 string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return "", fmt.Errorf("Error decode base64: %v", err)
	}
	key := "Vtdc@2024@2025#$"
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("Error cipher: %v", err)
	}

	if len(cipherText)%aes.BlockSize != 0 {
		return "", fmt.Errorf("False length string")
	}

	decrypted := make([]byte, len(cipherText))
	for bs, be := 0, block.BlockSize(); bs < len(cipherText); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Decrypt(decrypted[bs:be], cipherText[bs:be])
	}

	unpadded, err := pkcs7Unpadding(decrypted)
	if err != nil {
		return "", fmt.Errorf("Error unpadding: %v", err)
	}

	return string(unpadded), nil
}

// GetConfigFromFiles retrieves config options from file
func GetConfigFromFiles(configFilePaths []string) (Config, error) {
	var cfg Config

	// Read all specified config files in order. Values from later config files
	// will overwrite values from earlier ones.
	for _, configFilePath := range configFilePaths {
		config, err := os.Open(configFilePath)
		if err != nil {
			klog.Errorf("Failed to open OpenStack configuration file: %v", err)
			return cfg, err
		}
		defer config.Close()

		err = gcfg.FatalOnly(gcfg.ReadInto(&cfg, config))
		if err != nil {
			klog.Errorf("Failed to read OpenStack configuration file: %v", err)
			return cfg, err
		}
	}

	for _, global := range cfg.Global {
		// Update the config with data from clouds.yaml if UseClouds is enabled
		if global.UseClouds {
			if global.CloudsFile != "" {
				os.Setenv("OS_CLIENT_CONFIG_FILE", global.CloudsFile)
			}
			err := client.ReadClouds(global)
			if err != nil {
				return cfg, err
			}
			klog.V(5).Infof("Credentials are loaded from %s:", global.CloudsFile)
		}
	}

	return cfg, nil
}

const defaultMaxVolAttachLimit int64 = 256

var OsInstances map[string]IOpenStack
var configFiles = []string{"/etc/cloud.conf"}

func InitOpenStackProvider(cfgFiles []string, httpEndpoint string) {
	OsInstances = make(map[string]IOpenStack)
	metrics.RegisterMetrics("cinder-csi")
	if httpEndpoint != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", legacyregistry.HandlerWithReset())
		go func() {
			err := http.ListenAndServe(httpEndpoint, mux)
			if err != nil {
				klog.Fatalf("failed to listen & serve metrics from %q: %v", httpEndpoint, err)
			}
			klog.Infof("metrics available in %q", httpEndpoint)
		}()
	}

	configFiles = cfgFiles
	klog.V(2).Infof("InitOpenStackProvider configFiles: %s", configFiles)
}

type CredentialResponse struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
	Url    string `json:"url"`
}

func FetchCredentialsFromAPI(apiURL string, token string, payload map[string]interface{}) (string, string, string, error) {
	// Chuyển payload sang JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Tạo request POST với header Authorization
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	// Thực hiện request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Đọc và giải mã phản hồi
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read response body: %v", err)
	}

	var creds CredentialResponse
	if err := json.Unmarshal(body, &creds); err != nil {
		return "", "", "", fmt.Errorf("failed to decode response: %v", err)
	}

	return creds.Url, creds.ID, creds.Secret, nil
}

// CreateOpenStackProvider creates Openstack Instance with custom Global config param
func CreateOpenStackProvider(cloudName string) (IOpenStack, error) {
	// Get config from file
	cfg, err := GetConfigFromFiles(configFiles)
	if err != nil {
		klog.Errorf("GetConfigFromFiles %s failed with error: %v", configFiles, err)
		return nil, err
	}
	logcfg(cfg)
	global := cfg.Global[cloudName]
	if global == nil {
		return nil, fmt.Errorf("GetConfigFromFiles cloud name \"%s\" not found in configuration files: %s", cloudName, configFiles)
	}

	// if no search order given, use default
	if len(cfg.Metadata.SearchOrder) == 0 {
		cfg.Metadata.SearchOrder = fmt.Sprintf("%s,%s", metadata.ConfigDriveID, metadata.MetadataID)
	}

	//for k, v := range cfg.Global {
	//	klog.Infof("Bien global : Secret key = %s, value = %s", k, v)
	//}
	//
	//klog.Infof("Bien global 3: cloud config = %+v", global)

	payload := map[string]interface{}{
		"customerId": global.CustomerId,
		"clusterId":  global.ClusterId,
		"planType":   "k8s",
	}
	token, errSecret := DecryptECB(global.Token)

	credential := global.Url + "/api/v1/kubernetes/cluster/block-storage/credential"
	url, id, secret, err := FetchCredentialsFromAPI(credential, token, payload)

	decryptedSecret, errSecret := DecryptECB(secret)
	if errSecret != nil {
		fmt.Println("Error:", errSecret)
	} else {
		global.ApplicationCredentialSecret = decryptedSecret
	}

	decryptedId, errId := DecryptECB(id)
	if errId != nil {
		fmt.Println("Error:", errId)
	} else {
		global.ApplicationCredentialID = decryptedId
	}

	decryptedURL, errURL := DecryptECB(url)
	if errURL != nil {
		fmt.Println("Error:", errId)
	} else {
		global.AuthURL = decryptedURL
	}
	//klog.Infof("Bien global 4: cloud config = %+v", global)

	provider, err := client.NewOpenStackClient(global, "cinder-csi-plugin", userAgentData...)
	if err != nil {
		return nil, err
	}

	epOpts := gophercloud.EndpointOpts{
		Region:       global.Region,
		Availability: global.EndpointType,
	}

	// Init Nova ServiceClient
	computeclient, err := openstack.NewComputeV2(provider, epOpts)
	if err != nil {
		return nil, err
	}

	// Init Cinder ServiceClient
	blockstorageclient, err := openstack.NewBlockStorageV3(provider, epOpts)
	if err != nil {
		return nil, err
	}

	// Init OpenStack
	OsInstances[cloudName] = &OpenStack{
		compute:      computeclient,
		blockstorage: blockstorageclient,
		bsOpts:       cfg.BlockStorage,
		epOpts:       epOpts,
		metadataOpts: cfg.Metadata,
	}

	return OsInstances[cloudName], nil
}

// GetOpenStackProvider returns Openstack Instance
func GetOpenStackProvider(cloudName string) (IOpenStack, error) {
	OsInstance, OsInstanceDefined := OsInstances[cloudName]
	if OsInstanceDefined {
		return OsInstance, nil
	}
	OsInstance, err := CreateOpenStackProvider(cloudName)
	if err != nil {
		return nil, err
	}

	return OsInstance, nil
}

// GetMetadataOpts returns metadataopts
func (os *OpenStack) GetMetadataOpts() metadata.Opts {
	return os.metadataOpts
}
