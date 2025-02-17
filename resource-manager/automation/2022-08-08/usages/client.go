package usages

import (
	"fmt"

	"github.com/hashicorp/go-azure-sdk/sdk/client/resourcemanager"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type UsagesClient struct {
	Client *resourcemanager.Client
}

func NewUsagesClientWithBaseURI(api environments.Api) (*UsagesClient, error) {
	client, err := resourcemanager.NewResourceManagerClient(api, "usages", defaultApiVersion)
	if err != nil {
		return nil, fmt.Errorf("instantiating UsagesClient: %+v", err)
	}

	return &UsagesClient{
		Client: client,
	}, nil
}
