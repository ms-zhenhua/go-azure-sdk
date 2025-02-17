package servicetaskresource

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ServiceTasksCancelOperationResponse struct {
	HttpResponse *http.Response
	Model        *ProjectTask
}

// ServiceTasksCancel ...
func (c ServiceTaskResourceClient) ServiceTasksCancel(ctx context.Context, id ServiceTaskId) (result ServiceTasksCancelOperationResponse, err error) {
	req, err := c.preparerForServiceTasksCancel(ctx, id)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicetaskresource.ServiceTaskResourceClient", "ServiceTasksCancel", nil, "Failure preparing request")
		return
	}

	result.HttpResponse, err = c.Client.Send(req, azure.DoRetryWithRegistration(c.Client))
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicetaskresource.ServiceTaskResourceClient", "ServiceTasksCancel", result.HttpResponse, "Failure sending request")
		return
	}

	result, err = c.responderForServiceTasksCancel(result.HttpResponse)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicetaskresource.ServiceTaskResourceClient", "ServiceTasksCancel", result.HttpResponse, "Failure responding to request")
		return
	}

	return
}

// preparerForServiceTasksCancel prepares the ServiceTasksCancel request.
func (c ServiceTaskResourceClient) preparerForServiceTasksCancel(ctx context.Context, id ServiceTaskId) (*http.Request, error) {
	queryParameters := map[string]interface{}{
		"api-version": defaultApiVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithBaseURL(c.baseUri),
		autorest.WithPath(fmt.Sprintf("%s/cancel", id.ID())),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// responderForServiceTasksCancel handles the response to the ServiceTasksCancel request. The method always
// closes the http.Response Body.
func (c ServiceTaskResourceClient) responderForServiceTasksCancel(resp *http.Response) (result ServiceTasksCancelOperationResponse, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result.Model),
		autorest.ByClosing())
	result.HttpResponse = resp

	return
}
