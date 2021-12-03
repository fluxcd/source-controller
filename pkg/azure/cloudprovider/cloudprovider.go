/*
  MIT License

  Copyright (c) Microsoft Corporation. All rights reserved.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE
*/
// based on https://github.com/Azure/aad-pod-identity/blob/0fbc00f8b572ee780199ddb4489a94f1f01d3815/pkg/cloudprovider/cloudprovider.go

package cloudprovider

import (
	"fmt"
	"os"
	"strings"

	"github.com/Azure/aad-pod-identity/pkg/config"
	"github.com/Azure/aad-pod-identity/pkg/utils"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"gopkg.in/yaml.v2"
	"k8s.io/klog/v2"
)

// Client is a cloud provider client
type Client struct {
	Config     config.AzureConfig
	configFile string
	Authorizer autorest.Authorizer
}

// NewCloudProvider returns a azure cloud provider client
func NewCloudProvider(configFile string) (*Client, error) {
	client := &Client{
		configFile: configFile,
	}
	if err := client.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize cloud provider client, error: %+v", err)
	}
	return client, nil
}

// Init initializes the cloud provider client based
// on a config path or environment variables
func (c *Client) Init() error {
	c.Config = config.AzureConfig{}
	if c.configFile != "" {
		klog.V(6).Info("populating AzureConfig from azure.json")
		bytes, err := os.ReadFile(c.configFile)
		if err != nil {
			return fmt.Errorf("failed to config file %s, error: %+v", c.configFile, err)
		}
		if err = yaml.Unmarshal(bytes, &c.Config); err != nil {
			return fmt.Errorf("failed to unmarshal JSON, error: %+v", err)
		}
	} else {
		klog.V(6).Info("populating AzureConfig from secret/environment variables")
		c.Config.Cloud = os.Getenv("CLOUD")
		c.Config.TenantID = os.Getenv("TENANT_ID")
		c.Config.ClientID = os.Getenv("CLIENT_ID")
		c.Config.ClientSecret = os.Getenv("CLIENT_SECRET")
		c.Config.SubscriptionID = os.Getenv("SUBSCRIPTION_ID")
		c.Config.ResourceGroupName = os.Getenv("RESOURCE_GROUP")
		c.Config.VMType = os.Getenv("VM_TYPE")
		c.Config.UseManagedIdentityExtension = strings.EqualFold(os.Getenv("USE_MSI"), "True")
		c.Config.UserAssignedIdentityID = os.Getenv("USER_ASSIGNED_MSI_CLIENT_ID")
	}

	azureEnv, err := azure.EnvironmentFromName(c.Config.Cloud)
	if err != nil {
		return fmt.Errorf("failed to get cloud environment, error: %+v", err)
	}

	err = adal.AddToUserAgent("flux-source-controller")
	if err != nil {
		return fmt.Errorf("failed to add flux-source-controller to user agent, error: %+v", err)
	}

	oauthConfig, err := adal.NewOAuthConfig(azureEnv.ActiveDirectoryEndpoint, c.Config.TenantID)
	if err != nil {
		return fmt.Errorf("failed to create OAuth config, error: %+v", err)
	}

	var spt *adal.ServicePrincipalToken
	if c.Config.UseManagedIdentityExtension {
		// MSI endpoint is required for both types of MSI - system assigned and user assigned.
		msiEndpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return fmt.Errorf("failed to get MSI endpoint, error: %+v", err)
		}
		// UserAssignedIdentityID is empty, so we are going to use system assigned MSI
		if c.Config.UserAssignedIdentityID == "" {
			klog.Infof("MIC using system assigned identity for authentication.")
			spt, err = adal.NewServicePrincipalTokenFromMSI(msiEndpoint, azureEnv.ResourceManagerEndpoint)
			if err != nil {
				return fmt.Errorf("failed to get token from system-assigned identity, error: %+v", err)
			}
		} else { // User assigned identity usage.
			klog.Infof("MIC using user assigned identity: %s for authentication.", utils.RedactClientID(c.Config.UserAssignedIdentityID))
			spt, err = adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint, azureEnv.ResourceManagerEndpoint, c.Config.UserAssignedIdentityID)
			if err != nil {
				return fmt.Errorf("failed to get token from user-assigned identity, error: %+v", err)
			}
		}
	} else { // This is the default scenario - use service principal to get the token.
		spt, err = adal.NewServicePrincipalToken(
			*oauthConfig,
			c.Config.ClientID,
			c.Config.ClientSecret,
			azureEnv.ResourceManagerEndpoint,
		)
		if err != nil {
			return fmt.Errorf("failed to get service principal token, error: %+v", err)
		}
	}

	c.Authorizer = autorest.NewBearerAuthorizer(spt)
	return nil
}
