package servers

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ServerForUpdate struct {
	Location   *string                    `json:"location,omitempty"`
	Properties *ServerPropertiesForUpdate `json:"properties,omitempty"`
	Sku        *Sku                       `json:"sku,omitempty"`
	Tags       *map[string]string         `json:"tags,omitempty"`
}
