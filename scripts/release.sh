#!/usr/bin/env bash
# `make release`: build the notarized Mac app here (`make dist`) and publish it as a GitHub
# release, tagged v<MARKETING_VERSION> on the commit it was built from.
#
# Checked before the build, which takes minutes: a release whose tag points at a commit
# other than the one built, or that overwrites an earlier version, is worse than none.
set -u

ZIP=build/dist/WiFiDetect.zip
APP=build/dist/export/WiFiDetect.app

fail() {
    echo "release: $*" >&2
    exit 1
}

[ -z "$(git status --porcelain)" ] || fail "the working tree has changes; commit them first, so the build matches a commit"
HEAD=$(git rev-parse HEAD)
REMOTE=$(git ls-remote origin refs/heads/main | cut -f1)
# gh tags the commit on GitHub, so it has to be there, and be what main is.
[ "$REMOTE" = "$HEAD" ] || fail "GitHub's main (${REMOTE:-empty}) isn't HEAD ($HEAD); push main first"
gh auth status >/dev/null 2>&1 || fail "gh isn't signed in; run gh auth login"
VERSION=$(rg -o --color never 'MARKETING_VERSION: "([^"]+)"' -r '$1' project.yml)
[ -n "$VERSION" ] || fail "no MARKETING_VERSION in project.yml"
TAG="v$VERSION"
if gh release view "$TAG" >/dev/null 2>&1; then
    fail "$TAG is already released; raise MARKETING_VERSION in project.yml"
fi

make dist || fail "make dist failed"
xcrun stapler validate "$APP" >/dev/null || fail "the app has no notarization ticket"
BUILT=$(plutil -extract CFBundleShortVersionString raw "$APP/Contents/Info.plist")
[ "$BUILT" = "$VERSION" ] || fail "the app says $BUILT, project.yml $VERSION"

gh release create "$TAG" "$ZIP" --target "$HEAD" --title "WiFiDetect $VERSION" \
    --notes "${NOTES:-WiFiDetect $VERSION for macOS 26 or later, signed with Developer ID and notarized by Apple. Unzip and move WiFiDetect to Applications.}" \
    || fail "gh release create failed"
echo "== released $TAG"
