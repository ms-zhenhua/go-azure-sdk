package replicationprotectionintents

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ReplicationProtectionIntentProviderSpecificSettings interface {
}

func unmarshalReplicationProtectionIntentProviderSpecificSettingsImplementation(input []byte) (ReplicationProtectionIntentProviderSpecificSettings, error) {
	if input == nil {
		return nil, nil
	}

	var temp map[string]interface{}
	if err := json.Unmarshal(input, &temp); err != nil {
		return nil, fmt.Errorf("unmarshaling ReplicationProtectionIntentProviderSpecificSettings into map[string]interface: %+v", err)
	}

	value, ok := temp["instanceType"].(string)
	if !ok {
		return nil, nil
	}

	if strings.EqualFold(value, "A2A") {
		var out A2AReplicationIntentDetails
		if err := json.Unmarshal(input, &out); err != nil {
			return nil, fmt.Errorf("unmarshaling into A2AReplicationIntentDetails: %+v", err)
		}
		return out, nil
	}

	type RawReplicationProtectionIntentProviderSpecificSettingsImpl struct {
		Type   string                 `json:"-"`
		Values map[string]interface{} `json:"-"`
	}
	out := RawReplicationProtectionIntentProviderSpecificSettingsImpl{
		Type:   value,
		Values: temp,
	}
	return out, nil

}
