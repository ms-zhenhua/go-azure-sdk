package batchmanagements

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type LocationCheckNameAvailabilityOperationResponse struct {
	HttpResponse *http.Response
	Model        *CheckNameAvailabilityResult
}

// LocationCheckNameAvailability ...
func (c BatchManagementsClient) LocationCheckNameAvailability(ctx context.Context, id LocationId, input CheckNameAvailabilityParameters) (result LocationCheckNameAvailabilityOperationResponse, err error) {
	req, err := c.preparerForLocationCheckNameAvailability(ctx, id, input)
	if err != nil {
		err = autorest.NewErrorWithError(err, "batchmanagements.BatchManagementsClient", "LocationCheckNameAvailability", nil, "Failure preparing request")
		return
	}

	result.HttpResponse, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
	if err != nil {
		err = autorest.NewErrorWithError(err, "batchmanagements.BatchManagementsClient", "LocationCheckNameAvailability", result.HttpResponse, "Failure sending request")
		return
	}

	result, err = c.responderForLocationCheckNameAvailability(result.HttpResponse)
	if err != nil {
		err = autorest.NewErrorWithError(err, "batchmanagements.BatchManagementsClient", "LocationCheckNameAvailability", result.HttpResponse, "Failure responding to request")
		return
	}

	return
}

// preparerForLocationCheckNameAvailability prepares the LocationCheckNameAvailability request.
func (c BatchManagementsClient) preparerForLocationCheckNameAvailability(ctx context.Context, id LocationId, input CheckNameAvailabilityParameters) (*http.Request, error) {
	queryParameters := map[string]interface{}{
		"api-version": defaultApiVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(c.baseUri),
		autorest.WithPath(fmt.Sprintf("%s/checkNameAvailability", id.ID())),
		autorest.WithJSON(input),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// responderForLocationCheckNameAvailability handles the response to the LocationCheckNameAvailability request. The method always
// closes the http.Response Body.
func (c BatchManagementsClient) responderForLocationCheckNameAvailability(resp *http.Response) (result LocationCheckNameAvailabilityOperationResponse, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result.Model),
		autorest.ByClosing())
	result.HttpResponse = resp

	return
}
