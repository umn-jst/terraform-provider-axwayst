package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestAccBusinessUnits(t *testing.T) {
	res1name := "test-bu-" + acctest.RandString(5)

	resource1 := BusinessUnitsAPIModel{
		Name:                       res1name,
		BaseFolder:                 "/axway_home/" + res1name,
		BusinessUnitHierarchy:      res1name,
		BaseFolderModifyingAllowed: false,
		HomeFolderModifyingAllowed: false,
		EnabledIcapServers:         []string{},
		AdditionalAttributes:       map[string]string{},
		BandwidthLimits: BuBandwidthLimitsAPIModel{
			Policy: "default",
		},
		HtmlTemplateSettings: BuHtmlTemplateSettingsAPIModel{
			HtmlTemplateFolderPath: "Default HTML Template",
			IsAllowedForModifying:  false,
		},
		TransfersApiSettings: BuTransferAPISettingsAPIModel{
			IsWebServiceRightsModifyingAllowed: false,
		},
		AdHocSettings: BuAdHocSettingsAPIModel{
			AuthByEmail:                    false,
			AuthByEmailModifyingAllowed:    false,
			DeliveryMethodModifyingAllowed: false,
			DeliveryMethod:                 "DEFAULT",
			EnrollmentTypes:                []string{},
			EnrollmentTemplate:             "default",
		},
		FileArchivingSettings: BuFileArchiveSettingsAPIModel{
			Policy:                      "default",
			PolicyModifyingAllowed:      false,
			FolderPolicy:                "default",
			CustomFolder:                "",
			EncryptionCertificatePolicy: "default",
			CustomFileSizePolicy:        "default",
			CustomFileSize:              0,
		},
		LoginRestrictionSettings: BuLoginRestrictionSettingsAPIModel{
			IsPolicyModifyingAllowed: false,
		},
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_1_0), // built-in check from tfversion package
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccBUResource1Config(resource1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("name"),
						knownvalue.StringExact(resource1.Name),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("base_folder"),
						knownvalue.StringExact(resource1.BaseFolder),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("business_unit_hierarchy"),
						knownvalue.StringExact(resource1.BusinessUnitHierarchy),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("base_folder_modifying_allowed"),
						knownvalue.Bool(resource1.BaseFolderModifyingAllowed),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("home_folder_modifying_allowed"),
						knownvalue.Bool(resource1.HomeFolderModifyingAllowed),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("enabled_icap_servers"),
						knownvalue.SetExact([]knownvalue.Check{}),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("additional_attributes"),
						knownvalue.MapExact(map[string]knownvalue.Check{}),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("bandwidth_limits"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"policy": knownvalue.StringExact("default"),
						}),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("html_template_settings"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"html_template_folder_path": knownvalue.StringExact("Default HTML Template"),
							"is_allowed_for_modifying":  knownvalue.Bool(false),
						}),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("transfers_api_settings"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"is_web_service_rights_modifying_allowed": knownvalue.Bool(false),
						}),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("adhoc_settings"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"auth_by_email":                     knownvalue.Bool(false),
							"auth_by_email_modifying_allowed":   knownvalue.Bool(false),
							"delivery_method_modifying_allowed": knownvalue.Bool(false),
							"delivery_method":                   knownvalue.StringExact("DEFAULT"),
							"enrollment_types":                  knownvalue.SetExact([]knownvalue.Check{}),
							"enrollment_template":               knownvalue.StringExact("default"),
						}),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("file_archiving_settings"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"policy":                        knownvalue.StringExact("default"),
							"policy_modifying_allowed":      knownvalue.Bool(false),
							"folder_policy":                 knownvalue.StringExact("default"),
							"custom_folder":                 knownvalue.StringExact(""),
							"encryption_certificate_policy": knownvalue.StringExact("default"),
							"custom_file_size_policy":       knownvalue.StringExact("default"),
							"custom_file_size":              knownvalue.Int32Exact(0),
						}),
					),
					statecheck.ExpectKnownValue(
						"axwayst_business_units.test1",
						tfjsonpath.New("login_restriction_settings"),
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"is_policy_modifying_allowed": knownvalue.Bool(false),
						}),
					),
				},
			},
		},
	})
}

func testAccBUResource1Config(resource BusinessUnitsAPIModel) string {
	return fmt.Sprintf(`
resource "axwayst_business_units" "test1" {
  name		= "%s"
  base_folder	= "%s"
}
  `, resource.Name, resource.BaseFolder)
}
