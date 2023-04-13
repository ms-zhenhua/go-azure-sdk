package operations

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type MetricSpecification struct {
	AggregationType                 *string      `json:"aggregationType,omitempty"`
	Category                        *string      `json:"category,omitempty"`
	Dimensions                      *[]Dimension `json:"dimensions,omitempty"`
	DisplayDescription              *string      `json:"displayDescription,omitempty"`
	DisplayName                     *string      `json:"displayName,omitempty"`
	FillGapWithZero                 *bool        `json:"fillGapWithZero,omitempty"`
	Name                            *string      `json:"name,omitempty"`
	ResourceIdDimensionNameOverride *string      `json:"resourceIdDimensionNameOverride,omitempty"`
	Unit                            *string      `json:"unit,omitempty"`
}
