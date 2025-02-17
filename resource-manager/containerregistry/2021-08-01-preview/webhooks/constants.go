package webhooks

import "strings"

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ProvisioningState string

const (
	ProvisioningStateCanceled  ProvisioningState = "Canceled"
	ProvisioningStateCreating  ProvisioningState = "Creating"
	ProvisioningStateDeleting  ProvisioningState = "Deleting"
	ProvisioningStateFailed    ProvisioningState = "Failed"
	ProvisioningStateSucceeded ProvisioningState = "Succeeded"
	ProvisioningStateUpdating  ProvisioningState = "Updating"
)

func PossibleValuesForProvisioningState() []string {
	return []string{
		string(ProvisioningStateCanceled),
		string(ProvisioningStateCreating),
		string(ProvisioningStateDeleting),
		string(ProvisioningStateFailed),
		string(ProvisioningStateSucceeded),
		string(ProvisioningStateUpdating),
	}
}

func parseProvisioningState(input string) (*ProvisioningState, error) {
	vals := map[string]ProvisioningState{
		"canceled":  ProvisioningStateCanceled,
		"creating":  ProvisioningStateCreating,
		"deleting":  ProvisioningStateDeleting,
		"failed":    ProvisioningStateFailed,
		"succeeded": ProvisioningStateSucceeded,
		"updating":  ProvisioningStateUpdating,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := ProvisioningState(input)
	return &out, nil
}

type WebhookAction string

const (
	WebhookActionChartDelete WebhookAction = "chart_delete"
	WebhookActionChartPush   WebhookAction = "chart_push"
	WebhookActionDelete      WebhookAction = "delete"
	WebhookActionPush        WebhookAction = "push"
	WebhookActionQuarantine  WebhookAction = "quarantine"
)

func PossibleValuesForWebhookAction() []string {
	return []string{
		string(WebhookActionChartDelete),
		string(WebhookActionChartPush),
		string(WebhookActionDelete),
		string(WebhookActionPush),
		string(WebhookActionQuarantine),
	}
}

func parseWebhookAction(input string) (*WebhookAction, error) {
	vals := map[string]WebhookAction{
		"chart_delete": WebhookActionChartDelete,
		"chart_push":   WebhookActionChartPush,
		"delete":       WebhookActionDelete,
		"push":         WebhookActionPush,
		"quarantine":   WebhookActionQuarantine,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := WebhookAction(input)
	return &out, nil
}

type WebhookStatus string

const (
	WebhookStatusDisabled WebhookStatus = "disabled"
	WebhookStatusEnabled  WebhookStatus = "enabled"
)

func PossibleValuesForWebhookStatus() []string {
	return []string{
		string(WebhookStatusDisabled),
		string(WebhookStatusEnabled),
	}
}

func parseWebhookStatus(input string) (*WebhookStatus, error) {
	vals := map[string]WebhookStatus{
		"disabled": WebhookStatusDisabled,
		"enabled":  WebhookStatusEnabled,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := WebhookStatus(input)
	return &out, nil
}
