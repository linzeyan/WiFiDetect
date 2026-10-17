# WiFiDetect — macOS network diagnostics (Wi-Fi signal, traffic, HTTP(S) debugging)
#
#   make build      # generate the project and build app + helper
#   make test       # unit tests
#   make ios        # build the iPhone companion
#   make ipa        # App Store build of the iPhone and iPad app, not uploaded
#   make run        # launch the app
#   make logs       # what the app and the helper logged in the last 10 minutes
#   make release    # make dist, then a GitHub release of it
#   make strings    # new interface strings into the catalogs; fails on untranslated ones
#
# WiFiDetect.xcodeproj is generated from project.yml via xcodegen — it is not
# hand-edited and not committed. Edit project.yml, then `make generate`.

PROJECT       := WiFiDetect.xcodeproj
SCHEME        := WiFiDetect
CONFIGURATION := Debug
DERIVED       := build
APP           := $(DERIVED)/Build/Products/$(CONFIGURATION)/$(SCHEME).app
SUBSYSTEM     := com.zeyanlin.wifidetect
# Automatic signing may need to create or refresh the Mac development certificate
# or profile; without this flag xcodebuild fails instead of asking Xcode to do it.
XCB_FLAGS     := -project $(PROJECT) -scheme $(SCHEME) -configuration $(CONFIGURATION) \
                 -derivedDataPath $(DERIVED) -destination 'platform=macOS' -allowProvisioningUpdates

.DEFAULT_GOAL := help
.PHONY: help generate geoip build test ios ipa strings dist release run logs check-reject clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'

generate: geoip ## Regenerate WiFiDetect.xcodeproj from project.yml (source of truth)
	xcodegen generate

# Country and ASN lookups bundle DB-IP Lite (CC BY 4.0; the app credits it). Fetched
# once into a git-ignored folder before the project is generated, so xcodegen picks the
# files up as resources. Delete App/GeoIP to fetch the current month again.
GEOIP_MONTH ?= $(shell date +%Y-%m)
geoip: App/GeoIP/dbip-country-lite.mmdb App/GeoIP/dbip-asn-lite.mmdb ## Fetch the DB-IP Lite databases

App/GeoIP/dbip-%-lite.mmdb:
	@mkdir -p App/GeoIP
	curl -fsSL "https://download.db-ip.com/free/dbip-$*-lite-$(GEOIP_MONTH).mmdb.gz" | gunzip > $@.tmp
	mv $@.tmp $@

build: generate ## Build the app with the helper embedded
	xcodebuild $(XCB_FLAGS) build

test: generate ## Run unit tests
	xcodebuild $(XCB_FLAGS) test -only-testing:WiFiDetectTests

# The iPhone companion. IOS_DEST: 'generic/platform=iOS Simulator' (default) or
# 'generic/platform=iOS' for a device.
IOS_DEST ?= generic/platform=iOS Simulator
ios: generate ## Build the iPhone companion
	xcodebuild -project $(PROJECT) -scheme WiFiDetectCompanion -configuration $(CONFIGURATION) \
		-derivedDataPath $(DERIVED) -destination '$(IOS_DEST)' -allowProvisioningUpdates build

# The App Store build, written to disk and not uploaded: Transporter or Xcode's Organizer
# sends it. -allowProvisioningUpdates lets the export get the distribution certificate and
# App Store profile from the team's account. The export packs the .ipa with /usr/bin/rsync,
# which starts its other end from the first rsync in PATH; Homebrew's doesn't take Apple's
# -E and the export fails with "Copy failed", so /usr/bin goes first.
IPA_ARCHIVE := $(DERIVED)/ipa/WiFiDetectCompanion.xcarchive
ipa: generate ## App Store build of the iPhone and iPad app: build/ipa/WiFiDetectCompanion.ipa (not uploaded)
	rm -rf $(DERIVED)/ipa
	xcodebuild -project $(PROJECT) -scheme WiFiDetectCompanion -configuration Release \
		-derivedDataPath $(DERIVED) -destination 'generic/platform=iOS' -allowProvisioningUpdates \
		-archivePath $(IPA_ARCHIVE) archive
	PATH="/usr/bin:$$PATH" xcodebuild -exportArchive -archivePath $(IPA_ARCHIVE) -exportPath $(DERIVED)/ipa \
		-exportOptionsPlist scripts/ExportOptions-ios.plist -allowProvisioningUpdates

# The interface is Traditional Chinese and English (project.yml). Xcode merges new
# strings into the catalogs as it builds; xcodebuild leaves that to this.
strings: build ios ## Merge new interface strings into the catalogs; fail on any without a translation
	swift scripts/strings.swift

# The Developer ID build: the network extension and its entitlements come only with it,
# since a development build can't carry them onto a Mac that isn't a registered device.
dist: generate ## Developer ID build with the network extension, notarized: build/dist/WiFiDetect.zip
	bash scripts/dist.sh

# The Mac app ships on GitHub Releases, built and notarized on this Mac rather than in
# CI: the Developer ID certificate and the notarytool profile live in this keychain.
release: ## make dist, then publish build/dist/WiFiDetect.zip as GitHub release v<MARKETING_VERSION>
	bash scripts/release.sh

run: build ## Build and launch the app
	open $(APP)

logs: ## Show app + helper logs from the last 10 minutes
	log show --last 10m --info --style compact --predicate 'subsystem == "$(SUBSYSTEM)"'

check-reject: ## Probe B: a client not signed by our team must be rejected by the helper
	@mkdir -p $(DERIVED)
	swiftc -o $(DERIVED)/xpc-reject-check scripts/xpc-reject-check.swift
	$(DERIVED)/xpc-reject-check

clean: ## Remove build artifacts
	rm -rf $(DERIVED)
