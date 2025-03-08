package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

type AxwaySTClient struct {
	client   *http.Client
	endpoint string
	auth     string
}

// Used by the resource_business_units.go in the Create() and Update() functions to move data from a TF object to a JSON object.
func (c *AxwaySTClient) BusinessUnitDataPopulate(ctx context.Context, data BusinessUnitsModel) (bodyData BusinessUnitsAPIModel, diags diag.Diagnostics) {

	bodyData.Name = data.Name.ValueString()
	bodyData.BaseFolder = data.BaseFolder.ValueString()
	bodyData.Parent = data.Parent.ValueString()
	bodyData.BusinessUnitHierarchy = data.BusinessUnitHierarchy.ValueString()
	bodyData.BaseFolderModifyingAllowed = data.BaseFolderModifyingAllowed.ValueBool()
	bodyData.HomeFolderModifyingAllowed = data.HomeFolderModifyingAllowed.ValueBool()
	bodyData.DMZ = data.DMZ.ValueString()
	bodyData.ManagedByCG = data.ManagedByCG.ValueBool()

	var additionalAttr map[string]string
	diags = data.AdditionalAttributes.ElementsAs(ctx, &additionalAttr, false)
	if diags.HasError() {
		return
	}

	if len(additionalAttr) > 0 {
		bodyData.AdditionalAttributes = additionalAttr
	}

	var icapServers []string
	diags = data.EnabledIcapServers.ElementsAs(ctx, &icapServers, false)
	if diags.HasError() {
		return
	}

	if len(icapServers) > 0 {
		bodyData.EnabledIcapServers = icapServers
	}

	var bandwidthData BuBandwidthLimitsModel
	diags = data.BandwidthLimits.As(ctx, &bandwidthData, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.BandwidthLimits.Policy = bandwidthData.Policy.ValueString()
	bodyData.BandwidthLimits.ModifyLimitsAllowed = bandwidthData.ModifyLimitsAllowed.ValueBool()
	bodyData.BandwidthLimits.InboundLimit = bandwidthData.InboundLimit.ValueInt32()
	bodyData.BandwidthLimits.OutboundLimit = bandwidthData.OutboundLimit.ValueInt32()

	var htmlSettings BuHtmlTemplateSettingsModel

	diags = data.HtmlTemplateSettings.As(ctx, &htmlSettings, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.HtmlTemplateSettings.HtmlTemplateFolderPath = htmlSettings.HtmlTemplateFolderPath.ValueString()
	bodyData.HtmlTemplateSettings.IsAllowedForModifying = htmlSettings.IsAllowedForModifying.ValueBool()

	var transferAPISettings BuTransferAPISettingsModel

	diags = data.TransfersApiSettings.As(ctx, &transferAPISettings, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.TransfersApiSettings.TransfersWebServiceAllowed = transferAPISettings.TransfersWebServiceAllowed.ValueBool()
	bodyData.TransfersApiSettings.IsWebServiceRightsModifyingAllowed = transferAPISettings.IsWebServiceRightsModifyingAllowed.ValueBool()

	var adhocSettings BuAdHocSettingsModel

	diags = data.AdHocSettings.As(ctx, &adhocSettings, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.AdHocSettings.AuthByEmail = adhocSettings.AuthByEmail.ValueBool()
	bodyData.AdHocSettings.AuthByEmailModifyingAllowed = adhocSettings.AuthByEmailModifyingAllowed.ValueBool()
	bodyData.AdHocSettings.DeliveryMethodModifyingAllowed = adhocSettings.DeliveryMethodModifyingAllowed.ValueBool()
	bodyData.AdHocSettings.DeliveryMethod = adhocSettings.DeliveryMethod.ValueString()
	bodyData.AdHocSettings.ImplicitEnrollmentType = adhocSettings.ImplicitEnrollmentType.ValueString()
	bodyData.AdHocSettings.EnrollmentTemplate = adhocSettings.EnrollmentTemplate.ValueString()
	bodyData.AdHocSettings.NotificationTemplate = adhocSettings.NotificationTemplate.ValueString()

	var enrlTypes []string
	diags = adhocSettings.EnrollmentTypes.ElementsAs(ctx, &enrlTypes, false)
	if diags.HasError() {
		return
	}
	bodyData.AdHocSettings.EnrollmentTypes = enrlTypes

	var fileArchiveSettings BuFileArchiveSettingsModel

	diags = data.FileArchivingSettings.As(ctx, &fileArchiveSettings, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.FileArchivingSettings.Policy = fileArchiveSettings.Policy.ValueString()
	bodyData.FileArchivingSettings.FolderPolicy = fileArchiveSettings.FolderPolicy.ValueString()
	bodyData.FileArchivingSettings.EncryptionCertificatePolicy = fileArchiveSettings.EncryptionCertificatePolicy.ValueString()
	bodyData.FileArchivingSettings.CustomFileSizePolicy = fileArchiveSettings.CustomFileSizePolicy.ValueString()
	bodyData.FileArchivingSettings.CustomFileSize = fileArchiveSettings.CustomFileSize.ValueInt32()
	bodyData.FileArchivingSettings.PolicyModifyingAllowed = fileArchiveSettings.PolicyModifyingAllowed.ValueBool()
	bodyData.FileArchivingSettings.CustomFolder = fileArchiveSettings.CustomFolder.ValueString()
	bodyData.FileArchivingSettings.CustomEncryptionCertificate = fileArchiveSettings.CustomEncryptionCertificate.ValueString()

	var loginRestrictions BuLoginRestrictionSettingsModel

	diags = data.LoginRestrictionSettings.As(ctx, &loginRestrictions, basetypes.ObjectAsOptions{})
	if diags.HasError() {
		return
	}

	bodyData.LoginRestrictionSettings.Policy = loginRestrictions.Policy.ValueString()
	bodyData.LoginRestrictionSettings.IsPolicyModifyingAllowed = loginRestrictions.IsPolicyModifyingAllowed.ValueBool()

	return
}

// A wrapper for http.NewRequestWithContext() that prepends axwayst endpoint to URL & sets authorization
// headers and then makes the actual http request.
func (c *AxwaySTClient) GenericAPIRequest(ctx context.Context, method, url string, requestBody any, successCodes []int) (responseBody []byte, statusCode int, errorMessage error) {
	url = c.endpoint + url

	var body io.Reader

	if requestBody != nil {
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			errorMessage = fmt.Errorf("unable to marshal requestBody into json: %s", err.Error())
			return
		}

		body = strings.NewReader(string(jsonData))
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		errorMessage = fmt.Errorf("error generating http request: %v", err)
		return
	}
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("Authorization", c.auth)

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		errorMessage = fmt.Errorf("error doing http request: %v", err)
		return
	}

	var success bool
	for _, successCode := range successCodes {
		if httpResp.StatusCode == successCode {
			success = true
		}
	}

	responseBody, err = io.ReadAll(httpResp.Body)
	statusCode = httpResp.StatusCode

	if err != nil {
		errorMessage = fmt.Errorf("unable to read the http response data body. body: %v", responseBody)
		return
	}
	defer httpResp.Body.Close()

	if !success {
		errorMessage = fmt.Errorf("expected %v http response code for API call, got %d with message %s", successCodes, statusCode, responseBody)
		return
	}

	return
}

func (c *AxwaySTClient) CreateUpdateAPIRequest(ctx context.Context, method, url string, requestBody any, successCodes []int) (statusCode int, errorMessage error) {
	url = c.endpoint + url

	var body io.Reader

	if requestBody != nil {
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			errorMessage = fmt.Errorf("unable to marshal requestBody into json: %s", err.Error())
			return
		}

		body = strings.NewReader(string(jsonData))
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		errorMessage = fmt.Errorf("error generating http request: %v", err)
		return
	}
	httpReq.Header.Add("Content-Type", "application/json")
	httpReq.Header.Add("Authorization", c.auth)

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		errorMessage = fmt.Errorf("error doing http request: %v", err)
		return
	}

	var success bool
	for _, successCode := range successCodes {
		if httpResp.StatusCode == successCode {
			success = true
		}
	}

	if !success {
		body, err := io.ReadAll(httpResp.Body)
		defer httpResp.Body.Close()
		if err != nil {
			errorMessage = errors.New("unable to read http request response body to retrieve error message")
			return
		}
		errorMessage = fmt.Errorf("expected %v http response code for API call, got %d with message %s", successCodes, httpResp.StatusCode, body)
		return
	}

	statusCode = httpResp.StatusCode
	return
}
