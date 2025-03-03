package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type AdministratorsModel struct {
	AdministratorRights types.Object `tfsdk:"administrator_rights"`
	BusinessUnits       types.Set    `tfsdk:"business_units"`
	CertificateDn       types.String `tfsdk:"certificate_dn"`
	DualAuthentication  types.Bool   `tfsdk:"dual_authentication"`
	FullCreationPath    types.String `tfsdk:"full_creation_path"`
	IsLimited           types.Bool   `tfsdk:"is_limited"`
	LocalAuthentication types.Bool   `tfsdk:"local_authentication"`
	Locked              types.Bool   `tfsdk:"locked"`
	LoginName           types.String `tfsdk:"id"`
	Parent              types.String `tfsdk:"parent"`
	PasswordCredentials types.Object `tfsdk:"password_credentials"`
	RoleName            types.String `tfsdk:"role_name"`
}

type AdministratorsAPIModel struct {
	AdministratorRights AdministratorsRightsAPIModel             `json:"administratorRights"`
	BusinessUnits       []string                                 `json:"businessUnits"`
	CertificateDn       string                                   `json:"certificateDN"`
	DualAuthentication  bool                                     `json:"dualAuthentication"`
	FullCreationPath    string                                   `json:"fullCreationPath"`
	IsLimited           bool                                     `json:"isLimited"`
	LocalAuthentication bool                                     `json:"localAuthentication"`
	Locked              bool                                     `json:"locked"`
	LoginName           string                                   `json:"loginName"`
	Parent              string                                   `json:"parent"`
	PasswordCredentials AdministratorsPasswordCredentialAPIModel `json:"passwordCredentials"`
	RoleName            string                                   `json:"roleName"`
}

type AdministratorsPasswordCredentialAPIModel struct {
	Password        string `json:"password"`
	PasswordExpired bool   `json:"passwordExpired"`
}

type AdministratorsRightsAPIModel struct {
	CanReadOnly                          bool `json:"canReadOnly"`
	IsMaker                              bool `json:"isMaker"`
	IsChecker                            bool `json:"isChecker"`
	CanCreateUsers                       bool `json:"canCreateUsers"`
	CanUpdateUsers                       bool `json:"canUpdateUsers"`
	CanAccessHelpDesk                    bool `json:"canAccessHelpDesk"`
	CanSeeFullAuditLog                   bool `json:"canSeeFullAuditLog"`
	CanManageAdministrators              bool `json:"canManageAdministrators"`
	CanManageApplications                bool `json:"canManageApplications"`
	CanManageSharedFolders               bool `json:"canManageSharedFolders"`
	CanManageBusinessUnits               bool `json:"canManageBusinessUnits"`
	CanManageRouteTemplates              bool `json:"canManageRouteTemplates"`
	CanManageExternalScriptStep          bool `json:"canManageExternalScriptStep"`
	CanManageExternalScriptRootExecution bool `json:"canManageExternalScriptRootExecution"`
	CanManageLoginRestrictionPolicies    bool `json:"canManageLoginRestrictionPolicies"`
	CanManageIcapSettings                bool `json:"canManageIcapSettings"`
}
