package domain

type TenantDesiredState string

const (
	TenantDesiredStateEnabled  TenantDesiredState = "enabled"
	TenantDesiredStateDisabled TenantDesiredState = "disabled"
	TenantDesiredStateDeleted  TenantDesiredState = "deleted"
)

type TenantRuntimeState string

const (
	TenantRuntimeStateProvisioning TenantRuntimeState = "provisioning"
	TenantRuntimeStateReady        TenantRuntimeState = "ready"
	TenantRuntimeStateDegraded     TenantRuntimeState = "degraded"
	TenantRuntimeStateDisabled     TenantRuntimeState = "disabled"
	TenantRuntimeStateDeleting     TenantRuntimeState = "deleting"
)

func BuildTenantInstanceName(serviceID, subjectKey string) string {
	return "mcp-" + serviceID + "-" + subjectKey
}

func BuildTenantSecretPath(subjectKey, serviceID, secretKey string) string {
	return "/subjects/" + subjectKey + "/services/" + serviceID + "/" + secretKey
}
