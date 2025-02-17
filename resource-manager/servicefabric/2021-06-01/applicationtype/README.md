
## `github.com/hashicorp/go-azure-sdk/resource-manager/servicefabric/2021-06-01/applicationtype` Documentation

The `applicationtype` SDK allows for interaction with the Azure Resource Manager Service `servicefabric` (API Version `2021-06-01`).

This readme covers example usages, but further information on [using this SDK can be found in the project root](https://github.com/hashicorp/go-azure-sdk/tree/main/docs).

### Import Path

```go
import "github.com/hashicorp/go-azure-sdk/resource-manager/servicefabric/2021-06-01/applicationtype"
```


### Client Initialization

```go
client := applicationtype.NewApplicationTypeClientWithBaseURI("https://management.azure.com")
client.Client.Authorizer = authorizer
```


### Example Usage: `ApplicationTypeClient.CreateOrUpdate`

```go
ctx := context.TODO()
id := applicationtype.NewApplicationTypeID("12345678-1234-9876-4563-123456789012", "example-resource-group", "clusterValue", "applicationTypeValue")

payload := applicationtype.ApplicationTypeResource{
	// ...
}


read, err := client.CreateOrUpdate(ctx, id, payload)
if err != nil {
	// handle the error
}
if model := read.Model; model != nil {
	// do something with the model/response object
}
```


### Example Usage: `ApplicationTypeClient.Delete`

```go
ctx := context.TODO()
id := applicationtype.NewApplicationTypeID("12345678-1234-9876-4563-123456789012", "example-resource-group", "clusterValue", "applicationTypeValue")

if err := client.DeleteThenPoll(ctx, id); err != nil {
	// handle the error
}
```


### Example Usage: `ApplicationTypeClient.Get`

```go
ctx := context.TODO()
id := applicationtype.NewApplicationTypeID("12345678-1234-9876-4563-123456789012", "example-resource-group", "clusterValue", "applicationTypeValue")

read, err := client.Get(ctx, id)
if err != nil {
	// handle the error
}
if model := read.Model; model != nil {
	// do something with the model/response object
}
```


### Example Usage: `ApplicationTypeClient.List`

```go
ctx := context.TODO()
id := applicationtype.NewClusterID("12345678-1234-9876-4563-123456789012", "example-resource-group", "clusterValue")

read, err := client.List(ctx, id)
if err != nil {
	// handle the error
}
if model := read.Model; model != nil {
	// do something with the model/response object
}
```
