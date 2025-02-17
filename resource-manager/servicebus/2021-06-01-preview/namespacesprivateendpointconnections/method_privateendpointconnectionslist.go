package namespacesprivateendpointconnections

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-azure-sdk/sdk/client"
	"github.com/hashicorp/go-azure-sdk/sdk/odata"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type PrivateEndpointConnectionsListOperationResponse struct {
	HttpResponse *http.Response
	OData        *odata.OData
	Model        *[]PrivateEndpointConnection
}

type PrivateEndpointConnectionsListCompleteResult struct {
	Items []PrivateEndpointConnection
}

// PrivateEndpointConnectionsList ...
func (c NamespacesPrivateEndpointConnectionsClient) PrivateEndpointConnectionsList(ctx context.Context, id NamespaceId) (result PrivateEndpointConnectionsListOperationResponse, err error) {
	opts := client.RequestOptions{
		ContentType: "application/json",
		ExpectedStatusCodes: []int{
			http.StatusOK,
		},
		HttpMethod: http.MethodGet,
		Path:       fmt.Sprintf("%s/privateEndpointConnections", id.ID()),
	}

	req, err := c.Client.NewRequest(ctx, opts)
	if err != nil {
		return
	}

	var resp *client.Response
	resp, err = req.ExecutePaged(ctx)
	if resp != nil {
		result.OData = resp.OData
		result.HttpResponse = resp.Response
	}
	if err != nil {
		return
	}

	var values struct {
		Values *[]PrivateEndpointConnection `json:"values"`
	}
	if err = resp.Unmarshal(&values); err != nil {
		return
	}

	result.Model = values.Values

	return
}

// PrivateEndpointConnectionsListComplete retrieves all the results into a single object
func (c NamespacesPrivateEndpointConnectionsClient) PrivateEndpointConnectionsListComplete(ctx context.Context, id NamespaceId) (PrivateEndpointConnectionsListCompleteResult, error) {
	return c.PrivateEndpointConnectionsListCompleteMatchingPredicate(ctx, id, PrivateEndpointConnectionOperationPredicate{})
}

// PrivateEndpointConnectionsListCompleteMatchingPredicate retrieves all the results and then applies the predicate
func (c NamespacesPrivateEndpointConnectionsClient) PrivateEndpointConnectionsListCompleteMatchingPredicate(ctx context.Context, id NamespaceId, predicate PrivateEndpointConnectionOperationPredicate) (result PrivateEndpointConnectionsListCompleteResult, err error) {
	items := make([]PrivateEndpointConnection, 0)

	resp, err := c.PrivateEndpointConnectionsList(ctx, id)
	if err != nil {
		err = fmt.Errorf("loading results: %+v", err)
		return
	}
	if resp.Model != nil {
		for _, v := range *resp.Model {
			if predicate.Matches(v) {
				items = append(items, v)
			}
		}
	}

	result = PrivateEndpointConnectionsListCompleteResult{
		Items: items,
	}
	return
}
