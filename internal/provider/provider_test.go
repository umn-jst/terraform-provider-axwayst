package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"axwayst": providerserver.NewProtocol6WithError(New("test")()),
}

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("AXWAYST_HOST"); v == "" {
		t.Fatal("AXWAYST_HOST must be set for acceptance tests")
	}
	if v := os.Getenv("AXWAYST_USERNAME"); v == "" {
		t.Fatal("AXWAYST_USERNAME must be set for acceptance tests")
	}
	if v := os.Getenv("AXWAYST_PASSWORD"); v == "" {
		t.Fatal("AXWAYST_PASSWORD must be set for acceptance tests")
	}
}
