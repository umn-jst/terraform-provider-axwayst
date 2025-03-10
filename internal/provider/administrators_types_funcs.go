package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
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
	CertificateDn       string                                   `json:"certificateDN,omitempty"`
	DualAuthentication  bool                                     `json:"dualAuthentication"`
	FullCreationPath    string                                   `json:"fullCreationPath,omitempty"`
	IsLimited           bool                                     `json:"isLimited"`
	LocalAuthentication bool                                     `json:"localAuthentication"`
	Locked              bool                                     `json:"locked"`
	LoginName           string                                   `json:"loginName"`
	Parent              string                                   `json:"parent,omitempty"`
	PasswordCredentials AdministratorsPasswordCredentialAPIModel `json:"passwordCredentials"`
	RoleName            string                                   `json:"roleName"`
}

type AdministratorsPasswordCredentialAPIModel struct {
	Password        string `json:"password"`
	PasswordExpired bool   `json:"passwordExpired"`
}

type AdministratorsPasswordCredentialModel struct {
	Password        types.String `tfsdk:"password"`
	PasswordExpired types.Bool   `tfsdk:"password_expired"`
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

type AdministratorsRightsModel struct {
	CanReadOnly                          types.Bool `tfsdk:"can_read_only"`
	IsMaker                              types.Bool `tfsdk:"is_maker"`
	IsChecker                            types.Bool `tfsdk:"is_checker"`
	CanCreateUsers                       types.Bool `tfsdk:"can_create_users"`
	CanUpdateUsers                       types.Bool `tfsdk:"can_update_users"`
	CanAccessHelpDesk                    types.Bool `tfsdk:"can_access_help_desk"`
	CanSeeFullAuditLog                   types.Bool `tfsdk:"can_see_full_audit_log"`
	CanManageAdministrators              types.Bool `tfsdk:"can_manage_administrators"`
	CanManageApplications                types.Bool `tfsdk:"can_manage_applications"`
	CanManageSharedFolders               types.Bool `tfsdk:"can_manage_shared_folders"`
	CanManageBusinessUnits               types.Bool `tfsdk:"can_manage_business_units"`
	CanManageRouteTemplates              types.Bool `tfsdk:"can_manage_route_templates"`
	CanManageExternalScriptStep          types.Bool `tfsdk:"can_manage_external_script_step"`
	CanManageExternalScriptRootExecution types.Bool `tfsdk:"can_manage_external_script_root_execution"`
	CanManageLoginRestrictionPolicies    types.Bool `tfsdk:"can_manage_login_restriction_policies"`
	CanManageIcapSettings                types.Bool `tfsdk:"can_manage_icap_settings"`
}

// Used by the resource_administrators.go in the Create() and Update() functions to move data from a TF object to a JSON object.
func administratorsDataPopulate(ctx context.Context, data AdministratorsModel) (bodyData AdministratorsAPIModel, diags diag.Diagnostics) {

	bodyData.LoginName = data.LoginName.ValueString()
	bodyData.RoleName = data.RoleName.ValueString()
	bodyData.IsLimited = data.IsLimited.ValueBool()
	bodyData.LocalAuthentication = data.LocalAuthentication.ValueBool()
	bodyData.DualAuthentication = data.DualAuthentication.ValueBool()
	bodyData.Locked = data.Locked.ValueBool()
	// if !(data.Parent.IsNull()) {
	bodyData.Parent = data.Parent.ValueString()
	// }
	// if !(data.CertificateDn.IsNull()) {
	bodyData.CertificateDn = data.CertificateDn.ValueString()
	// }

	// if !(data.FullCreationPath.IsNull()) {
	bodyData.FullCreationPath = data.FullCreationPath.ValueString()
	// }

	var businessUnits []string
	diags = data.BusinessUnits.ElementsAs(ctx, &businessUnits, false)
	if diags.HasError() {
		return
	}
	bodyData.BusinessUnits = businessUnits

	var passCreds AdministratorsPasswordCredentialModel

	diags = data.PasswordCredentials.As(ctx, &passCreds, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.PasswordCredentials.Password = passCreds.Password.ValueString()
	bodyData.PasswordCredentials.PasswordExpired = passCreds.PasswordExpired.ValueBool()

	var adminRights AdministratorsRightsModel

	diags = data.AdministratorRights.As(ctx, &adminRights, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.AdministratorRights.CanReadOnly = adminRights.CanReadOnly.ValueBool()
	bodyData.AdministratorRights.IsMaker = adminRights.IsMaker.ValueBool()
	bodyData.AdministratorRights.IsChecker = adminRights.IsChecker.ValueBool()
	bodyData.AdministratorRights.CanCreateUsers = adminRights.CanCreateUsers.ValueBool()
	bodyData.AdministratorRights.CanUpdateUsers = adminRights.CanUpdateUsers.ValueBool()
	bodyData.AdministratorRights.CanAccessHelpDesk = adminRights.CanAccessHelpDesk.ValueBool()
	bodyData.AdministratorRights.CanSeeFullAuditLog = adminRights.CanSeeFullAuditLog.ValueBool()
	bodyData.AdministratorRights.CanManageAdministrators = adminRights.CanManageAdministrators.ValueBool()
	bodyData.AdministratorRights.CanManageApplications = adminRights.CanManageApplications.ValueBool()
	bodyData.AdministratorRights.CanManageSharedFolders = adminRights.CanManageSharedFolders.ValueBool()
	bodyData.AdministratorRights.CanManageBusinessUnits = adminRights.CanManageBusinessUnits.ValueBool()
	bodyData.AdministratorRights.CanManageRouteTemplates = adminRights.CanManageRouteTemplates.ValueBool()
	bodyData.AdministratorRights.CanManageExternalScriptStep = adminRights.CanManageExternalScriptStep.ValueBool()
	bodyData.AdministratorRights.CanManageExternalScriptRootExecution = adminRights.CanManageExternalScriptRootExecution.ValueBool()
	bodyData.AdministratorRights.CanManageLoginRestrictionPolicies = adminRights.CanManageLoginRestrictionPolicies.ValueBool()
	bodyData.AdministratorRights.CanManageIcapSettings = adminRights.CanManageIcapSettings.ValueBool()

	return
}
