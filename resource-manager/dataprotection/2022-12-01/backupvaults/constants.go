package backupvaults

import "strings"

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type AlertsState string

const (
	AlertsStateDisabled AlertsState = "Disabled"
	AlertsStateEnabled  AlertsState = "Enabled"
)

func PossibleValuesForAlertsState() []string {
	return []string{
		string(AlertsStateDisabled),
		string(AlertsStateEnabled),
	}
}

func parseAlertsState(input string) (*AlertsState, error) {
	vals := map[string]AlertsState{
		"disabled": AlertsStateDisabled,
		"enabled":  AlertsStateEnabled,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := AlertsState(input)
	return &out, nil
}

type CrossSubscriptionRestoreState string

const (
	CrossSubscriptionRestoreStateDisabled            CrossSubscriptionRestoreState = "Disabled"
	CrossSubscriptionRestoreStateEnabled             CrossSubscriptionRestoreState = "Enabled"
	CrossSubscriptionRestoreStatePermanentlyDisabled CrossSubscriptionRestoreState = "PermanentlyDisabled"
)

func PossibleValuesForCrossSubscriptionRestoreState() []string {
	return []string{
		string(CrossSubscriptionRestoreStateDisabled),
		string(CrossSubscriptionRestoreStateEnabled),
		string(CrossSubscriptionRestoreStatePermanentlyDisabled),
	}
}

func parseCrossSubscriptionRestoreState(input string) (*CrossSubscriptionRestoreState, error) {
	vals := map[string]CrossSubscriptionRestoreState{
		"disabled":            CrossSubscriptionRestoreStateDisabled,
		"enabled":             CrossSubscriptionRestoreStateEnabled,
		"permanentlydisabled": CrossSubscriptionRestoreStatePermanentlyDisabled,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := CrossSubscriptionRestoreState(input)
	return &out, nil
}

type ImmutabilityState string

const (
	ImmutabilityStateDisabled ImmutabilityState = "Disabled"
	ImmutabilityStateLocked   ImmutabilityState = "Locked"
	ImmutabilityStateUnlocked ImmutabilityState = "Unlocked"
)

func PossibleValuesForImmutabilityState() []string {
	return []string{
		string(ImmutabilityStateDisabled),
		string(ImmutabilityStateLocked),
		string(ImmutabilityStateUnlocked),
	}
}

func parseImmutabilityState(input string) (*ImmutabilityState, error) {
	vals := map[string]ImmutabilityState{
		"disabled": ImmutabilityStateDisabled,
		"locked":   ImmutabilityStateLocked,
		"unlocked": ImmutabilityStateUnlocked,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := ImmutabilityState(input)
	return &out, nil
}

type ProvisioningState string

const (
	ProvisioningStateFailed       ProvisioningState = "Failed"
	ProvisioningStateProvisioning ProvisioningState = "Provisioning"
	ProvisioningStateSucceeded    ProvisioningState = "Succeeded"
	ProvisioningStateUnknown      ProvisioningState = "Unknown"
	ProvisioningStateUpdating     ProvisioningState = "Updating"
)

func PossibleValuesForProvisioningState() []string {
	return []string{
		string(ProvisioningStateFailed),
		string(ProvisioningStateProvisioning),
		string(ProvisioningStateSucceeded),
		string(ProvisioningStateUnknown),
		string(ProvisioningStateUpdating),
	}
}

func parseProvisioningState(input string) (*ProvisioningState, error) {
	vals := map[string]ProvisioningState{
		"failed":       ProvisioningStateFailed,
		"provisioning": ProvisioningStateProvisioning,
		"succeeded":    ProvisioningStateSucceeded,
		"unknown":      ProvisioningStateUnknown,
		"updating":     ProvisioningStateUpdating,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := ProvisioningState(input)
	return &out, nil
}

type ResourceMoveState string

const (
	ResourceMoveStateCommitFailed    ResourceMoveState = "CommitFailed"
	ResourceMoveStateCommitTimedout  ResourceMoveState = "CommitTimedout"
	ResourceMoveStateCriticalFailure ResourceMoveState = "CriticalFailure"
	ResourceMoveStateFailed          ResourceMoveState = "Failed"
	ResourceMoveStateInProgress      ResourceMoveState = "InProgress"
	ResourceMoveStateMoveSucceeded   ResourceMoveState = "MoveSucceeded"
	ResourceMoveStatePartialSuccess  ResourceMoveState = "PartialSuccess"
	ResourceMoveStatePrepareFailed   ResourceMoveState = "PrepareFailed"
	ResourceMoveStatePrepareTimedout ResourceMoveState = "PrepareTimedout"
	ResourceMoveStateUnknown         ResourceMoveState = "Unknown"
)

func PossibleValuesForResourceMoveState() []string {
	return []string{
		string(ResourceMoveStateCommitFailed),
		string(ResourceMoveStateCommitTimedout),
		string(ResourceMoveStateCriticalFailure),
		string(ResourceMoveStateFailed),
		string(ResourceMoveStateInProgress),
		string(ResourceMoveStateMoveSucceeded),
		string(ResourceMoveStatePartialSuccess),
		string(ResourceMoveStatePrepareFailed),
		string(ResourceMoveStatePrepareTimedout),
		string(ResourceMoveStateUnknown),
	}
}

func parseResourceMoveState(input string) (*ResourceMoveState, error) {
	vals := map[string]ResourceMoveState{
		"commitfailed":    ResourceMoveStateCommitFailed,
		"committimedout":  ResourceMoveStateCommitTimedout,
		"criticalfailure": ResourceMoveStateCriticalFailure,
		"failed":          ResourceMoveStateFailed,
		"inprogress":      ResourceMoveStateInProgress,
		"movesucceeded":   ResourceMoveStateMoveSucceeded,
		"partialsuccess":  ResourceMoveStatePartialSuccess,
		"preparefailed":   ResourceMoveStatePrepareFailed,
		"preparetimedout": ResourceMoveStatePrepareTimedout,
		"unknown":         ResourceMoveStateUnknown,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := ResourceMoveState(input)
	return &out, nil
}

type SoftDeleteState string

const (
	SoftDeleteStateAlwaysOn SoftDeleteState = "AlwaysOn"
	SoftDeleteStateOff      SoftDeleteState = "Off"
	SoftDeleteStateOn       SoftDeleteState = "On"
)

func PossibleValuesForSoftDeleteState() []string {
	return []string{
		string(SoftDeleteStateAlwaysOn),
		string(SoftDeleteStateOff),
		string(SoftDeleteStateOn),
	}
}

func parseSoftDeleteState(input string) (*SoftDeleteState, error) {
	vals := map[string]SoftDeleteState{
		"alwayson": SoftDeleteStateAlwaysOn,
		"off":      SoftDeleteStateOff,
		"on":       SoftDeleteStateOn,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := SoftDeleteState(input)
	return &out, nil
}

type StorageSettingStoreTypes string

const (
	StorageSettingStoreTypesArchiveStore     StorageSettingStoreTypes = "ArchiveStore"
	StorageSettingStoreTypesOperationalStore StorageSettingStoreTypes = "OperationalStore"
	StorageSettingStoreTypesVaultStore       StorageSettingStoreTypes = "VaultStore"
)

func PossibleValuesForStorageSettingStoreTypes() []string {
	return []string{
		string(StorageSettingStoreTypesArchiveStore),
		string(StorageSettingStoreTypesOperationalStore),
		string(StorageSettingStoreTypesVaultStore),
	}
}

func parseStorageSettingStoreTypes(input string) (*StorageSettingStoreTypes, error) {
	vals := map[string]StorageSettingStoreTypes{
		"archivestore":     StorageSettingStoreTypesArchiveStore,
		"operationalstore": StorageSettingStoreTypesOperationalStore,
		"vaultstore":       StorageSettingStoreTypesVaultStore,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := StorageSettingStoreTypes(input)
	return &out, nil
}

type StorageSettingTypes string

const (
	StorageSettingTypesGeoRedundant     StorageSettingTypes = "GeoRedundant"
	StorageSettingTypesLocallyRedundant StorageSettingTypes = "LocallyRedundant"
	StorageSettingTypesZoneRedundant    StorageSettingTypes = "ZoneRedundant"
)

func PossibleValuesForStorageSettingTypes() []string {
	return []string{
		string(StorageSettingTypesGeoRedundant),
		string(StorageSettingTypesLocallyRedundant),
		string(StorageSettingTypesZoneRedundant),
	}
}

func parseStorageSettingTypes(input string) (*StorageSettingTypes, error) {
	vals := map[string]StorageSettingTypes{
		"georedundant":     StorageSettingTypesGeoRedundant,
		"locallyredundant": StorageSettingTypesLocallyRedundant,
		"zoneredundant":    StorageSettingTypesZoneRedundant,
	}
	if v, ok := vals[strings.ToLower(input)]; ok {
		return &v, nil
	}

	// otherwise presume it's an undefined value and best-effort it
	out := StorageSettingTypes(input)
	return &out, nil
}
