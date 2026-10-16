package test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hiddify/hiddify-core/v2/profile"
	"github.com/sagernet/sing-box/experimental/libbox"
)

func TestAddByContent(t *testing.T) {
	// Keep the import and metadata checks independent of a mutable upstream
	// subscription, which can change its title and supported protocols.
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(workingDir); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `//profile-title: base64:8J+UpSBXQVJQIPCflKU=
//profile-update-interval: 24
//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
//support-url: https://t.me/hiddify
//profile-web-page-url: https://hiddify.com
{"outbounds":[{"type":"socks","tag":"fixture","server":"127.0.0.1","server_port":1080}]}
`)
	}))
	t.Cleanup(server.Close)
	ctx := libbox.BaseContext(nil)
	entity, err := profile.AddByUrl(ctx, server.URL, "", false)
	if err != nil {
		t.Fatalf("expected no error, but got: %v", err)
	}
	fmt.Printf("entity: %v\n", entity)
	// Check if the content has been added correctly
	profileTitle := entity.Name
	expectedTitle := "🔥 WARP 🔥" // The Base64 decoded title
	if profileTitle != expectedTitle {
		t.Errorf("expected profile title to be %v, got %v", expectedTitle, profileTitle)
	}

	// Check subscription userinfo
	userInfo := entity.SubInfo
	if userInfo.Upload != 0 || userInfo.Download != 0 || userInfo.Total != 10737418240000000 || userInfo.Expire != 2546249531 {
		t.Errorf("subscription userinfo not parsed correctly, got: %v", userInfo)
	}

	// Check URLs
	supportURL := entity.SubInfo.SupportUrl
	if supportURL != "https://t.me/hiddify" {
		t.Errorf("expected support URL to be https://t.me/hiddify, got %v", supportURL)
	}

	profileWebPageURL := entity.SubInfo.WebPageUrl
	if profileWebPageURL != "https://hiddify.com" {
		t.Errorf("expected profile web page URL to be https://hiddify.com, got %v", profileWebPageURL)
	}
	profile.DeleteById(entity.Id)
	// You can further assert individual fields of warp configurations
}
