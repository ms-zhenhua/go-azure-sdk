package sourcecontrolsyncjob

import (
	"fmt"

	"github.com/hashicorp/go-azure-sdk/sdk/client/resourcemanager"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type SourceControlSyncJobClient struct {
	Client *resourcemanager.Client
}

func NewSourceControlSyncJobClientWithBaseURI(api environments.Api) (*SourceControlSyncJobClient, error) {
	client, err := resourcemanager.NewResourceManagerClient(api, "sourcecontrolsyncjob", defaultApiVersion)
	if err != nil {
		return nil, fmt.Errorf("instantiating SourceControlSyncJobClient: %+v", err)
	}

	return &SourceControlSyncJobClient{
		Client: client,
	}, nil
}
