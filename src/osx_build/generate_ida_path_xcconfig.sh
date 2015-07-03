#!/bin/sh

#  generate_ida_path_xcconfig.sh
#  HexRaysCodeXplorer
#
#  Created by Marc-Etienne M.Léveillé on 2015-06-20.
#  Copyright (c) 2015 Marc-Etienne M.Léveillé

IDA_APP_PATH="$(mdfind "kMDItemCFBundleIdentifier = com.hexrays.idaq" | head -1)"
IDA_SDK="$(dirname "$(dirname "$(mdfind IDB_EXT | grep '/ida.hpp$')")")"

if [ -z "$IDA_APP_PATH" ]; then
    echo "Could not determine idaq.app path." > /dev/stderr
fi

if [ -z "$IDA_SDK" ]; then
    echo "Could not determine IDA SDK path." > /dev/stderr
fi

(
    echo IDA_APP_PATH=\""$IDA_APP_PATH"\"
    echo IDA_SDK=\""$IDA_SDK"\"
) > "$SRCROOT/osx_build/ida_path.xcconfig"
