package python2package

import "strings"

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type ModuleProvisioningState string

const (
	ModuleProvisioningStateActivitiesStored            ModuleProvisioningState = "ActivitiesStored"
	ModuleProvisioningStateCancelled                   ModuleProvisioningState = "Cancelled"
	ModuleProvisioningStateConnectionTypeImported      ModuleProvisioningState = "ConnectionTypeImported"
	ModuleProvisioningStateContentDownloaded           ModuleProvisioningState = "ContentDownloaded"
	ModuleProvisioningStateContentRetrieved            ModuleProvisioningState = "ContentRetrieved"
	ModuleProvisioningStateContentStored               ModuleProvisioningState = "ContentStored"
	ModuleProvisioningStateContentValidated            ModuleProvisioningState = "ContentValidated"
	ModuleProvisioningStateCreated                     ModuleProvisioningState = "Created"
	ModuleProvisioningStateCreating                    ModuleProvisioningState = "Creating"
	ModuleProvisioningStateFailed                      ModuleProvisioningState = "Failed"
	ModuleProvisioningStateModuleDataStored            ModuleProvisioningState = "ModuleDataStored"
	ModuleProvisioningStateModuleImportRunbookComplete ModuleProvisioningState = "ModuleImportRunbookComplete"
	ModuleProvisioningStateRunningImportModuleRunbook  ModuleProvisioningState = "RunningImportModuleRunbook"
	ModuleProvisioningStateStartingImportModuleRunbook ModuleProvisioningState = "StartingImportModuleRunbook"
	ModuleProvisioningStateSucceeded                   ModuleProvisioningState = "Succeeded"
	ModuleProvisioningStateUpdating                    ModuleProvisioningState = "Updating"
)

func PossibleValuesForModuleProvisioningState() []string {
	return []string{
		string(ModuleProvisioningStateActivitiesStored),
		string(ModuleProvisioningStateCancelled),
		string(ModuleProvisioningStateConnectionTypeImported),
		string(ModuleProvisioningStateContentDownloaded),
		string(ModuleProvisioningStateContentRetrieved),
		string(ModuleProvisioningStateContentStored),
		string(ModuleProvisioningStateContentValidated),
		string(ModuleProvisioningStateCreated),
		string(ModuleProvisioningStateCreating),
		string(ModuleProvisioningStateFailed),
		string(ModuleProvisioningStateModuleDataStored),
		string(ModuleProvisioningStateModuleImportRunbookComplete),
		string(ModuleProvisioningStateRunningImportModuleRunbook),
		string(ModuleProvisioningStateStartingImportModuleRunbook),
		string(ModuleProvisioningStateSucceeded),
		string(ModuleProvisioningStateUpdating),
	}
}

func parseModuleProvisioningState(input string) (*ModuleProvisioningState, error) {
	vals := map[string]ModuleProvisioningState{
		"activitiesstored":            ModuleProvisioningStateActivitiesStored,
		"cancelled":                   ModuleProvisioningStateCancelled,
		"connectiontypeimported":      ModuleProvisioningStateConnectionTypeImported,
		"contentdownloaded":           ModuleProvisioningStateContentDownloaded,
		"contentretrieved":            ModuleProvisioningStateContentRetrieved,
		"contentstored":               ModuleProvisioningStateContentStored,
		"contentvalidated":            ModuleProvisioningStateContentValidated,
		"created":                     ModuleProvisioningStateCreated,
		"creating":                    ModuleProvisioningStateCreating,
		"failed":                      ModuleProvisioningStateFailed,
		"moduledatastored":            ModuleProvisioningStateModuleDataStored,
		"moduleimportrunbookcomplete": ModuleProvisioningStateModuleImportRunbookComplete,
		"runningimportmodulerunbook":  ModuleProvisioningStateRunningImportModuleRunbook,
		"startingimportmodulerunbook": ModuleProvisioningStateStartingImportModuleRunbook,
		"succeeded":                   ModuleProvisioningStateSucceeded,
		"updating":                    ModuleProvisioningStateUpdating,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := ModuleProvisioningState(input)
	return &out, nil
}
