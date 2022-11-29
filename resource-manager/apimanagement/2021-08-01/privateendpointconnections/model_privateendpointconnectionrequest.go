package privateendpointconnections

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type PrivateEndpointConnectionRequest struct {
	Id         *string                                     `json:"id,omitempty"`
	Properties *PrivateEndpointConnectionRequestProperties `json:"properties,omitempty"`
}
