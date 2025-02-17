package storagesyncservicesresource

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/hashicorp/go-azure-helpers/polling"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type StorageSyncServicesUpdateOperationResponse struct {
	Poller       polling.LongRunningPoller
	HttpResponse *http.Response
}

// StorageSyncServicesUpdate ...
func (c StorageSyncServicesResourceClient) StorageSyncServicesUpdate(ctx context.Context, id StorageSyncServiceId, input StorageSyncServiceUpdateParameters) (result StorageSyncServicesUpdateOperationResponse, err error) {
	req, err := c.preparerForStorageSyncServicesUpdate(ctx, id, input)
	if err != nil {
		err = autorest.NewErrorWithError(err, "storagesyncservicesresource.StorageSyncServicesResourceClient", "StorageSyncServicesUpdate", nil, "Failure preparing request")
		return
	}

	result, err = c.senderForStorageSyncServicesUpdate(ctx, req)
	if err != nil {
		err = autorest.NewErrorWithError(err, "storagesyncservicesresource.StorageSyncServicesResourceClient", "StorageSyncServicesUpdate", result.HttpResponse, "Failure sending request")
		return
	}

	return
}

// StorageSyncServicesUpdateThenPoll performs StorageSyncServicesUpdate then polls until it's completed
func (c StorageSyncServicesResourceClient) StorageSyncServicesUpdateThenPoll(ctx context.Context, id StorageSyncServiceId, input StorageSyncServiceUpdateParameters) error {
	result, err := c.StorageSyncServicesUpdate(ctx, id, input)
	if err != nil {
		return fmt.Errorf("performing StorageSyncServicesUpdate: %+v", err)
	}

	if err := result.Poller.PollUntilDone(); err != nil {
		return fmt.Errorf("polling after StorageSyncServicesUpdate: %+v", err)
	}

	return nil
}

// preparerForStorageSyncServicesUpdate prepares the StorageSyncServicesUpdate request.
func (c StorageSyncServicesResourceClient) preparerForStorageSyncServicesUpdate(ctx context.Context, id StorageSyncServiceId, input StorageSyncServiceUpdateParameters) (*http.Request, error) {
	queryParameters := map[string]interface{}{
		"api-version": defaultApiVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPatch(),
		autorest.WithBaseURL(c.baseUri),
		autorest.WithPath(id.ID()),
		autorest.WithJSON(input),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// senderForStorageSyncServicesUpdate sends the StorageSyncServicesUpdate request. The method will close the
// http.Response Body if it receives an error.
func (c StorageSyncServicesResourceClient) senderForStorageSyncServicesUpdate(ctx context.Context, req *http.Request) (future StorageSyncServicesUpdateOperationResponse, err error) {
	var resp *http.Response
	resp, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
	if err != nil {
		return
	}

	future.Poller, err = polling.NewPollerFromResponse(ctx, resp, c.Client, req.Method)
	return
}
