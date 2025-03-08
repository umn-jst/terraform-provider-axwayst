package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type BusinessUnitsModel struct {
	Name                              types.String `tfsdk:"name"`
	BaseFolder                        types.String `tfsdk:"base_folder"`
	Parent                            types.String `tfsdk:"parent"`
	BusinessUnitHierarchy             types.String `tfsdk:"business_unit_hierarchy"`
	BaseFolderModifyingAllowed        types.Bool   `tfsdk:"base_folder_modifying_allowed"`
	HomeFolderModifyingAllowed        types.Bool   `tfsdk:"home_folder_modifying_allowed"`
	DMZ                               types.String `tfsdk:"dmz"`
	ManagedByCG                       types.Bool   `tfsdk:"managed_by_cg"`
	EnabledIcapServers                types.Set    `tfsdk:"enabled_icap_servers"`
	AdditionalAttributes              types.Map    `tfsdk:"additional_attributes"`
	SharedFoldersCollaborationAllowed types.Bool   `tfsdk:"shared_folders_collaboration_allowed"`
	BandwidthLimits                   types.Object `tfsdk:"bandwidth_limits"`
	HtmlTemplateSettings              types.Object `tfsdk:"html_template_settings"`
	TransfersApiSettings              types.Object `tfsdk:"transfers_api_settings"`
	AdHocSettings                     types.Object `tfsdk:"adhoc_settings"`
	FileArchivingSettings             types.Object `tfsdk:"file_archiving_settings"`
	LoginRestrictionSettings          types.Object `tfsdk:"login_restriction_settings"`
}

type BusinessUnitsAPIModel struct {
	Name                              string                             `json:"name"`
	BaseFolder                        string                             `json:"baseFolder"`
	Parent                            string                             `json:"parent,omitempty"`
	BusinessUnitHierarchy             string                             `json:"businessUnitHierarchy"`
	BaseFolderModifyingAllowed        bool                               `json:"baseFolderModifyingAllowed"`
	HomeFolderModifyingAllowed        bool                               `json:"homeFolderModifyingAllowed"`
	DMZ                               string                             `json:"dmz,omitempty"`
	ManagedByCG                       bool                               `json:"managedByCG"`
	EnabledIcapServers                []string                           `json:"enabledIcapServers,omitempty"`
	AdditionalAttributes              map[string]string                  `json:"additionalAttributes,omitempty"`
	SharedFoldersCollaborationAllowed bool                               `json:"sharedFoldersCollaborationAllowed"`
	BandwidthLimits                   BuBandwidthLimitsAPIModel          `json:"bandwidthLimits"`
	HtmlTemplateSettings              BuHtmlTemplateSettingsAPIModel     `json:"htmlTemplateSettings"`
	TransfersApiSettings              BuTransferAPISettingsAPIModel      `json:"transfersApiSettings"`
	AdHocSettings                     BuAdHocSettingsAPIModel            `json:"adHocSettings"`
	FileArchivingSettings             BuFileArchiveSettingsAPIModel      `json:"fileArchivingSettings"`
	LoginRestrictionSettings          BuLoginRestrictionSettingsAPIModel `json:"loginRestrictionSettings"`
}

type BuBandwidthLimitsAPIModel struct {
	Policy              string `json:"policy"`
	ModifyLimitsAllowed bool   `json:"modifyLimitsAllowed,omitempty"`
	InboundLimit        int32  `json:"inboundLimit,omitempty"`
	OutboundLimit       int32  `json:"outboundLimit,omitempty"`
}

type BuBandwidthLimitsModel struct {
	Policy              types.String `tfsdk:"policy"`
	ModifyLimitsAllowed types.Bool   `tfsdk:"modify_limits_allowed"`
	InboundLimit        types.Int32  `tfsdk:"inbound_limit"`
	OutboundLimit       types.Int32  `tfsdk:"outbound_limit"`
}

type BuHtmlTemplateSettingsAPIModel struct {
	HtmlTemplateFolderPath string `json:"htmlTemplateFolderPath"`
	IsAllowedForModifying  bool   `json:"isAllowedForModifying"`
}

type BuHtmlTemplateSettingsModel struct {
	HtmlTemplateFolderPath types.String `tfsdk:"html_template_folder_path"`
	IsAllowedForModifying  types.Bool   `tfsdk:"is_allowed_for_modifying"`
}

type BuTransferAPISettingsAPIModel struct {
	TransfersWebServiceAllowed         bool `json:"transfersWebServiceAllowed"`
	IsWebServiceRightsModifyingAllowed bool `json:"isWebServiceRightsModifyingAllowed"`
}

type BuTransferAPISettingsModel struct {
	TransfersWebServiceAllowed         types.Bool `tfsdk:"transfers_web_service_allowed"`
	IsWebServiceRightsModifyingAllowed types.Bool `tfsdk:"is_web_service_rights_modifying_allowed"`
}

type BuAdHocSettingsAPIModel struct {
	AuthByEmail                    bool     `json:"authByEmail,omitempty"`
	AuthByEmailModifyingAllowed    bool     `json:"authByEmailModifyingAllowed,omitempty"`
	DeliveryMethodModifyingAllowed bool     `json:"deliveryMethodModifyingAllowed,omitempty"`
	DeliveryMethod                 string   `json:"deliveryMethod,omitempty"`
	EnrollmentTypes                []string `json:"enrollmentTypes,omitempty"`
	ImplicitEnrollmentType         string   `json:"implicitEnrollmentType,omitempty"`
	EnrollmentTemplate             string   `json:"enrollmentTemplate,omitempty"`
	NotificationTemplate           string   `json:"notificationTemplate,omitempty"`
}

type BuAdHocSettingsModel struct {
	AuthByEmail                    types.Bool   `tfsdk:"auth_by_email"`
	AuthByEmailModifyingAllowed    types.Bool   `tfsdk:"auth_by_email_modifying_allowed"`
	DeliveryMethodModifyingAllowed types.Bool   `tfsdk:"delivery_method_modifying_allowed"`
	DeliveryMethod                 types.String `tfsdk:"delivery_method"`
	EnrollmentTypes                types.Set    `tfsdk:"enrollment_types"`
	ImplicitEnrollmentType         types.String `tfsdk:"implicit_enrollment_type"`
	EnrollmentTemplate             types.String `tfsdk:"enrollment_template"`
	NotificationTemplate           types.String `tfsdk:"notification_template"`
}

type BuFileArchiveSettingsAPIModel struct {
	Policy                      string `json:"policy,omitempty"`
	FolderPolicy                string `json:"folderPolicy,omitempty"`
	EncryptionCertificatePolicy string `json:"encryptionCertificatePolicy,omitempty"`
	CustomFileSizePolicy        string `json:"customFileSizePolicy,omitempty"`
	CustomFileSize              int32  `json:"customFileSize,omitempty"`
	PolicyModifyingAllowed      bool   `json:"policyModifyingAllowed,omitempty"`
	CustomFolder                string `json:"customFolder,omitempty"`
	CustomEncryptionCertificate string `json:"customEncryptionCertificate,omitempty"`
}

type BuFileArchiveSettingsModel struct {
	Policy                      types.String `tfsdk:"policy"`
	FolderPolicy                types.String `tfsdk:"folder_policy"`
	EncryptionCertificatePolicy types.String `tfsdk:"encryption_certificate_policy"`
	CustomFileSizePolicy        types.String `tfsdk:"custom_file_size_policy"`
	CustomFileSize              types.Int32  `tfsdk:"custom_file_size"`
	PolicyModifyingAllowed      types.Bool   `tfsdk:"policy_modifying_allowed"`
	CustomFolder                types.String `tfsdk:"custom_folder"`
	CustomEncryptionCertificate types.String `tfsdk:"custom_encryption_certificate"`
}

type BuLoginRestrictionSettingsAPIModel struct {
	Policy                   string `json:"policy,omitempty"`
	IsPolicyModifyingAllowed bool   `json:"isPolicyModifyingAllowed,omitempty"`
}

type BuLoginRestrictionSettingsModel struct {
	Policy                   types.String `tfsdk:"policy"`
	IsPolicyModifyingAllowed types.Bool   `tfsdk:"is_policy_modifying_allowed"`
}

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
