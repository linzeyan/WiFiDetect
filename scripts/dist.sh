#!/usr/bin/env bash
# The Developer ID build with the network extension (`make dist`): archive, export for
# Developer ID, check the signatures, notarize, staple. Leaves build/dist/WiFiDetect.zip,
# ready to copy to /Applications on the Mac that runs it.
#
# Every step stops the script with what went wrong: a half-signed app that installs
# but whose extension macOS refuses is worse than none.
set -u

OUT=build/dist
TEAM=NKJSLB6HBR
EXTENSION=com.zeyanlin.wifidetect.extension
NOTARY_PROFILE=${NOTARY_PROFILE:-zeyanlin-notary}

fail() {
    echo "dist: $*" >&2
    exit 1
}

rm -rf "$OUT"
mkdir -p "$OUT"

# macOS replaces an installed system extension only when its version changes.
STAMP=$(date +%Y%m%d%H%M%S)
echo "== archive (extension version $STAMP)"
# Archived unsigned, signed to run locally here, and signed for real by the export:
# the Network Extension entitlements need a profile, a development one can only be
# made for a registered Mac, and automatic signing won't archive with Developer ID.
# Unsigned, Xcode leaves $(TeamIdentifierPrefix) empty, so it's given.
xcodebuild -project WiFiDetect.xcodeproj -scheme WiFiDetectDist -configuration Release \
    -derivedDataPath build/dist-derived -destination 'generic/platform=macOS' \
    -archivePath "$OUT/WiFiDetect.xcarchive" \
    CODE_SIGNING_ALLOWED=NO TeamIdentifierPrefix="$TEAM." CURRENT_PROJECT_VERSION="$STAMP" archive || fail "archive failed"

ARCHIVED="$OUT/WiFiDetect.xcarchive/Products/Applications/WiFiDetect.app"
expand() { sed "s/\$(TeamIdentifierPrefix)/$TEAM./g" "$1" >"$2"; }
expand Extension/Extension.entitlements "$OUT/extension.entitlements"
expand App/WiFiDetectDist.entitlements "$OUT/app.entitlements"
# Inside out, as the export re-signs them: the helper, the extension, the app.
codesign -f -s - -o runtime -i com.zeyanlin.wifidetect.helper "$ARCHIVED/Contents/MacOS/wifidetect-helper" \
    && codesign -f -s - -o runtime --entitlements "$OUT/extension.entitlements" "$ARCHIVED/Contents/Library/SystemExtensions/$EXTENSION.systemextension" \
    && codesign -f -s - -o runtime --entitlements "$OUT/app.entitlements" "$ARCHIVED" || fail "local signing failed"

cat >"$OUT/ExportOptions.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>developer-id</string>
    <key>signingStyle</key>
    <string>automatic</string>
    <key>teamID</key>
    <string>$TEAM</string>
</dict>
</plist>
EOF

echo "== export for Developer ID"
xcodebuild -exportArchive -archivePath "$OUT/WiFiDetect.xcarchive" -exportPath "$OUT/export" \
    -exportOptionsPlist "$OUT/ExportOptions.plist" -allowProvisioningUpdates || fail "export failed"

APP="$OUT/export/WiFiDetect.app"
SYSEXT="$APP/Contents/Library/SystemExtensions/$EXTENSION.systemextension"
[ -d "$SYSEXT" ] || fail "the app has no $EXTENSION.systemextension"

echo "== check signatures"
codesign --verify --deep --strict --verbose=2 "$APP" || fail "the signature doesn't verify"
for bundle in "$APP" "$SYSEXT"; do
    entitlements=$(codesign -d --entitlements - --xml "$bundle" 2>/dev/null)
    # A Developer ID profile allows only the -systemextension values; signed with the
    # plain ones, macOS refuses the extension at activation.
    for value in content-filter-provider-systemextension app-proxy-provider-systemextension; do
        rg -qF "<string>$value</string>" <<<"$entitlements" || fail "$bundle lacks the $value entitlement"
    done
    [ -f "$bundle/Contents/embedded.provisionprofile" ] || fail "$bundle has no embedded provisioning profile"
    codesign -dvv "$bundle" 2>&1 | rg -qF "Authority=Developer ID Application" || fail "$bundle isn't signed with Developer ID"
done
plutil -extract NetworkExtension.NEMachServiceName raw "$SYSEXT/Contents/Info.plist" | rg -q "^$TEAM\." \
    || fail "NEMachServiceName isn't under the team's app group"

ditto -c -k --keepParent "$APP" "$OUT/WiFiDetect.zip" || fail "zip failed"

echo "== notarize"
if ! xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
    echo "dist: signed but NOT notarized: couldn't read the notarytool keychain profile \"$NOTARY_PROFILE\"." >&2
    # notarytool says the profile is missing when the screen is merely locked: it can't
    # read the keychain item then, and once it was recreated for nothing.
    echo "      If this Mac's screen is locked, unlock it. Otherwise create the profile:" >&2
    echo "      xcrun notarytool store-credentials $NOTARY_PROFILE --apple-id <id> --team-id $TEAM" >&2
    echo "      then run make dist again. The unnotarized app is at $APP." >&2
    exit 2
fi
xcrun notarytool submit "$OUT/WiFiDetect.zip" --keychain-profile "$NOTARY_PROFILE" --wait || fail "notarization failed"
xcrun stapler staple "$APP" || fail "stapling failed"
# The zip can't carry a ticket itself; zipped again, the app inside has it.
rm "$OUT/WiFiDetect.zip"
ditto -c -k --keepParent "$APP" "$OUT/WiFiDetect.zip" || fail "zip failed"
spctl --assess --type execute --verbose "$APP" || fail "Gatekeeper rejects the app"
echo "== done: $OUT/WiFiDetect.zip"
