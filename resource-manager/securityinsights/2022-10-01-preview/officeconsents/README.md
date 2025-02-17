
## `github.com/hashicorp/go-azure-sdk/resource-manager/securityinsights/2022-10-01-preview/officeconsents` Documentation

The `officeconsents` SDK allows for interaction with the Azure Resource Manager Service `securityinsights` (API Version `2022-10-01-preview`).

This readme covers example usages, but further information on [using this SDK can be found in the project root](https://github.com/hashicorp/go-azure-sdk/tree/main/docs).

### Import Path

```go
import "github.com/hashicorp/go-azure-sdk/resource-manager/securityinsights/2022-10-01-preview/officeconsents"
```


### Client Initialization

```go
client := officeconsents.NewOfficeConsentsClientWithBaseURI("https://management.azure.com")
client.Client.Authorizer = authorizer
```


### Example Usage: `OfficeConsentsClient.OfficeConsentsDelete`

```go
ctx := context.TODO()
id := officeconsents.NewOfficeConsentID("12345678-1234-9876-4563-123456789012", "example-resource-group", "workspaceValue", "consentIdValue")

read, err := client.OfficeConsentsDelete(ctx, id)
if err != nil {
	// handle the error
}
if model := read.Model; model != nil {
	// do something with the model/response object
}
```


### Example Usage: `OfficeConsentsClient.OfficeConsentsGet`

```go
ctx := context.TODO()
id := officeconsents.NewOfficeConsentID("12345678-1234-9876-4563-123456789012", "example-resource-group", "workspaceValue", "consentIdValue")

read, err := client.OfficeConsentsGet(ctx, id)
if err != nil {
	// handle the error
}
if model := read.Model; model != nil {
	// do something with the model/response object
}
```


### Example Usage: `OfficeConsentsClient.OfficeConsentsList`

```go
ctx := context.TODO()
id := officeconsents.NewWorkspaceID("12345678-1234-9876-4563-123456789012", "example-resource-group", "workspaceValue")

// alternatively `client.OfficeConsentsList(ctx, id)` can be used to do batched pagination
items, err := client.OfficeConsentsListComplete(ctx, id)
if err != nil {
	// handle the error
}
for _, item := range items {
	// do something
}
```
