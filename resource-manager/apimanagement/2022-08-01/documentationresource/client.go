package documentationresource

import "github.com/Azure/go-autorest/autorest"

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type DocumentationResourceClient struct {
	Client  autorest.Client
	baseUri string
}

func NewDocumentationResourceClientWithBaseURI(endpoint string) DocumentationResourceClient {
	return DocumentationResourceClient{
		Client:  autorest.NewClientWithUserAgent(userAgent()),
		baseUri: endpoint,
	}
}
