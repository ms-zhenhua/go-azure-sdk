package waitstatistics

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-azure-helpers/resourcemanager/resourceids"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

var _ resourceids.ResourceId = WaitStatisticId{}

// WaitStatisticId is a struct representing the Resource ID for a Wait Statistic
type WaitStatisticId struct {
	SubscriptionId    string
	ResourceGroupName string
	ServerName        string
	WaitStatisticsId  string
}

// NewWaitStatisticID returns a new WaitStatisticId struct
func NewWaitStatisticID(subscriptionId string, resourceGroupName string, serverName string, waitStatisticsId string) WaitStatisticId {
	return WaitStatisticId{
		SubscriptionId:    subscriptionId,
		ResourceGroupName: resourceGroupName,
		ServerName:        serverName,
		WaitStatisticsId:  waitStatisticsId,
	}
}

// ParseWaitStatisticID parses 'input' into a WaitStatisticId
func ParseWaitStatisticID(input string) (*WaitStatisticId, error) {
	parser := resourceids.NewParserFromResourceIdType(WaitStatisticId{})
	parsed, err := parser.Parse(input, false)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := WaitStatisticId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, fmt.Errorf("the segment 'subscriptionId' was not found in the resource id %q", input)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, fmt.Errorf("the segment 'resourceGroupName' was not found in the resource id %q", input)
	}

	if id.ServerName, ok = parsed.Parsed["serverName"]; !ok {
		return nil, fmt.Errorf("the segment 'serverName' was not found in the resource id %q", input)
	}

	if id.WaitStatisticsId, ok = parsed.Parsed["waitStatisticsId"]; !ok {
		return nil, fmt.Errorf("the segment 'waitStatisticsId' was not found in the resource id %q", input)
	}

	return &id, nil
}

// ParseWaitStatisticIDInsensitively parses 'input' case-insensitively into a WaitStatisticId
// note: this method should only be used for API response data and not user input
func ParseWaitStatisticIDInsensitively(input string) (*WaitStatisticId, error) {
	parser := resourceids.NewParserFromResourceIdType(WaitStatisticId{})
	parsed, err := parser.Parse(input, true)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %+v", input, err)
	}

	var ok bool
	id := WaitStatisticId{}

	if id.SubscriptionId, ok = parsed.Parsed["subscriptionId"]; !ok {
		return nil, fmt.Errorf("the segment 'subscriptionId' was not found in the resource id %q", input)
	}

	if id.ResourceGroupName, ok = parsed.Parsed["resourceGroupName"]; !ok {
		return nil, fmt.Errorf("the segment 'resourceGroupName' was not found in the resource id %q", input)
	}

	if id.ServerName, ok = parsed.Parsed["serverName"]; !ok {
		return nil, fmt.Errorf("the segment 'serverName' was not found in the resource id %q", input)
	}

	if id.WaitStatisticsId, ok = parsed.Parsed["waitStatisticsId"]; !ok {
		return nil, fmt.Errorf("the segment 'waitStatisticsId' was not found in the resource id %q", input)
	}

	return &id, nil
}

// ValidateWaitStatisticID checks that 'input' can be parsed as a Wait Statistic ID
func ValidateWaitStatisticID(input interface{}, key string) (warnings []string, errors []error) {
	v, ok := input.(string)
	if !ok {
		errors = append(errors, fmt.Errorf("expected %q to be a string", key))
		return
	}

	if _, err := ParseWaitStatisticID(v); err != nil {
		errors = append(errors, err)
	}

	return
}

// ID returns the formatted Wait Statistic ID
func (id WaitStatisticId) ID() string {
	fmtString := "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforMariaDB/servers/%s/waitStatistics/%s"
	return fmt.Sprintf(fmtString, id.SubscriptionId, id.ResourceGroupName, id.ServerName, id.WaitStatisticsId)
}

// Segments returns a slice of Resource ID Segments which comprise this Wait Statistic ID
func (id WaitStatisticId) Segments() []resourceids.Segment {
	return []resourceids.Segment{
		resourceids.StaticSegment("staticSubscriptions", "subscriptions", "subscriptions"),
		resourceids.SubscriptionIdSegment("subscriptionId", "12345678-1234-9876-4563-123456789012"),
		resourceids.StaticSegment("staticResourceGroups", "resourceGroups", "resourceGroups"),
		resourceids.ResourceGroupSegment("resourceGroupName", "example-resource-group"),
		resourceids.StaticSegment("staticProviders", "providers", "providers"),
		resourceids.ResourceProviderSegment("staticMicrosoftDBforMariaDB", "Microsoft.DBforMariaDB", "Microsoft.DBforMariaDB"),
		resourceids.StaticSegment("staticServers", "servers", "servers"),
		resourceids.UserSpecifiedSegment("serverName", "serverValue"),
		resourceids.StaticSegment("staticWaitStatistics", "waitStatistics", "waitStatistics"),
		resourceids.UserSpecifiedSegment("waitStatisticsId", "waitStatisticsIdValue"),
	}
}

// String returns a human-readable description of this Wait Statistic ID
func (id WaitStatisticId) String() string {
	components := []string{
		fmt.Sprintf("Subscription: %q", id.SubscriptionId),
		fmt.Sprintf("Resource Group Name: %q", id.ResourceGroupName),
		fmt.Sprintf("Server Name: %q", id.ServerName),
		fmt.Sprintf("Wait Statistics: %q", id.WaitStatisticsId),
	}
	return fmt.Sprintf("Wait Statistic (%s)", strings.Join(components, "\n"))
}
