package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupKeepsBrowserUserData(t *testing.T) {
	keep := []string{
		"profile-id/Default/Sessions/Session_123",
		"profile-id/Default/Login Data",
		"profile-id/Default/Login Data For Account",
		"profile-id/Default/Cookies",
		"profile-id/Default/History",
		"profile-id/Default/Preferences",
		"profile-id/Local State",
		"profile-id/Default/Extensions/extension-id/manifest.json",
		"profile-id/Default/Local Extension Settings/extension-id/000003.log",
		"profile-id/Default/Extension State/000003.log",
		"profile-id/Default/IndexedDB/site.indexeddb.leveldb/000003.log",
		"profile-id/Default/Local Storage/leveldb/000003.log",
		"profile-id/Default/Session Storage/000003.log",
	}
	for _, rel := range keep {
		if shouldSkipBackupEntry(rel) {
			t.Fatalf("should keep browser user data: %s", rel)
		}
	}
}

func TestBackupSkipsBrowserCacheAndGeneratedModels(t *testing.T) {
	skip := []string{
		"profile-id/OptGuideOnDeviceModel/2025.8.8.1141/weights.bin",
		"profile-id/OptGuideOnDeviceClassifierModel/2026.2.12.1554/weights.bin",
		"profile-id/optimization_guide_model_store/43/model.tflite",
		"profile-id/Safe Browsing/UrlSoceng.store",
		"profile-id/Webstore Downloads/extension.crx",
		"profile-id/component_crx_cache/cache-file",
		"profile-id/Default/Cache/Cache_Data/data_0",
		"profile-id/Default/Code Cache/js/index",
		"profile-id/Default/GPUCache/data_0",
		"profile-id/Default/DawnWebGPUCache/data_0",
		"profile-id/Default/Service Worker/CacheStorage/cache-file",
		"profile-id/Default/Safe Browsing Network/store",
		"profile-id/Default/optimization_guide_hint_cache_store/store",
	}
	for _, rel := range skip {
		if !shouldSkipBackupEntry(rel) {
			t.Fatalf("should skip cache/generated data: %s", rel)
		}
	}
}

func TestRemoveLegacyVSCodeWindowOverrides(t *testing.T) {
	settings := map[string]any{
		"window.restoreWindows":         "none",
		"window.openFoldersInNewWindow": "on",
		"window.openFilesInNewWindow":   "on",
		"editor.fontSize":               float64(15),
	}
	removeLegacyVSCodeWindowOverrides(settings)
	for _, key := range []string{
		"window.restoreWindows",
		"window.openFoldersInNewWindow",
		"window.openFilesInNewWindow",
	} {
		if _, ok := settings[key]; ok {
			t.Fatalf("legacy VS Code window override was not removed: %s", key)
		}
	}
	if settings["editor.fontSize"] != float64(15) {
		t.Fatalf("unrelated setting was changed")
	}
}

func TestVSCodeSettingsAcceptsUTF8BOM(t *testing.T) {
	raw := append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"window.restoreWindows":"none"}`)...)
	var settings map[string]any
	if err := json.Unmarshal(trimUTF8BOM(raw), &settings); err != nil {
		t.Fatalf("settings with UTF-8 BOM should parse: %v", err)
	}
}

func TestClearManagedChromiumCacheKeepsUserData(t *testing.T) {
	profile := t.TempDir()
	cacheFile := filepath.Join(profile, "Default", "Cache", "Cache_Data", "data_0")
	keepFile := filepath.Join(profile, "Default", "Cookies")
	if err := os.MkdirAll(filepath.Dir(cacheFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacheFile, []byte("cache"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(keepFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keepFile, []byte("cookies"), 0644); err != nil {
		t.Fatal(err)
	}
	removed, err := clearManagedChromiumCache(profile)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if removed == 0 {
		t.Fatalf("expected at least one cache directory to be removed")
	}
	if _, err := os.Stat(cacheFile); !os.IsNotExist(err) {
		t.Fatalf("cache file should be removed, stat error: %v", err)
	}
	if _, err := os.Stat(keepFile); err != nil {
		t.Fatalf("user data should remain: %v", err)
	}
}

func TestPathInsideRejectsSiblings(t *testing.T) {
	root := filepath.Join(t.TempDir(), "profile")
	if pathInside(filepath.Join(root, "..", "other"), root) {
		t.Fatalf("sibling path should be rejected")
	}
	if !pathInside(filepath.Join(root, "Default", "Cache"), root) {
		t.Fatalf("profile child path should be accepted")
	}
}
