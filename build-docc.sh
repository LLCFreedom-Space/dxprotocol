##!/bin/sh

xcrun xcodebuild docbuild \
    -scheme DXProtocol \
    -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "$PWD/.derivedData"

xcrun docc process-archive transform-for-static-hosting \
    "$PWD/.derivedData/Build/Products/Debug-iphonesimulator/DXProtocol.doccarchive" \
    --output-path ".docs" \
    --hosting-base-path "dxprotocol"
echo '<script>window.location.href += "/documentation/dxprotocol"</script>' > .docs/index.html
