#!/bin/zsh

####################################################################################################
#
# Extension Attribute: Entra Platform SSO Registration Status (Lightweight)
#
# Description:
# This script is a lightweight Jamf Pro Extension Attribute used to report Microsoft Entra
# (Azure AD) Platform SSO registration status for the currently logged-in macOS user.
#
# The script queries the Jamf Conditional Access framework (`getPSSOStatus`) to determine
# whether the device and user are properly registered with Microsoft Entra and capable of
# satisfying Conditional Access requirements.
#
# The Extension Attribute returns the following information:
#
#   • Logged-in user
#   • User home directory
#   • Timestamp when the data was captured
#   • Primary network connection type (WiFi or LAN) based on macOS Network service priority
#   • Platform SSO registration status and interpretation
#   • JamfAAD Azure ID acquisition state
#   • Microsoft Entra tenant ID
#   • Device ID associated with the Entra registration
#   • SSO Extension full mode status
#   • Cloud authentication host
#   • User Principal Name (UPN)
#
# Optimization Notes:
# This script is intentionally optimized for Jamf Pro inventory performance.
# It avoids expensive operations such as:
#
#   • Enumerating all local users
#   • Performing keychain certificate scans
#   • Running unnecessary network calls
#
# Instead, it only inspects the active console user and uses native macOS
# frameworks to retrieve the required information.
#
# This makes the script safe to run during `jamf recon` across large fleets.
#
####################################################################################################

jamfCA="/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/Jamf Conditional Access.app/Contents/MacOS/JAMF Conditional Access"

runAsUser() {
    local uid="$1"
    shift
    /bin/launchctl asuser "$uid" "$@"
}

get_value() {
    local source="$1"
    local key="$2"
    printf '%s\n' "$source" | /usr/bin/awk -F ": " -v k="$key" '$1 == k {print $2; exit}'
}

captureTime=$(/bin/date "+%Y-%m-%d %H:%M:%S")

############################################
# Detect primary network type based on macOS service order
############################################

networkType="Offline"

serviceOrder=$(/usr/sbin/networksetup -listnetworkserviceorder 2>/dev/null)

primaryDevice=$(printf '%s\n' "$serviceOrder" | /usr/bin/awk '
    /Hardware Port:/ {
        line=$0
        port=""
        device=""

        if (match(line, /Hardware Port: ([^,]+)/)) {
            port=substr(line, RSTART + 15, RLENGTH - 15)
        }

        if (match(line, /Device: ([^)]+)/)) {
            device=substr(line, RSTART + 8, RLENGTH - 8)
        }

        if (port != "" && device != "") {
            print port "|" device
        }
    }
' | while IFS='|' read -r port device; do
    [[ -z "$device" ]] && continue

    ip=$(/usr/sbin/ipconfig getifaddr "$device" 2>/dev/null)
    if [[ -n "$ip" ]] || /sbin/ifconfig "$device" 2>/dev/null | /usr/bin/grep -q "status: active"; then
        echo "$port|$device"
        break
    fi
done)

if [[ -n "$primaryDevice" ]]; then
    primaryPort=${primaryDevice%%|*}

    case "$primaryPort" in
        "Wi-Fi"|"AirPort")
            networkType="WiFi"
            ;;
        "Ethernet"|"USB Ethernet"|"Thunderbolt Ethernet"|"LAN"|"USB 10/100/1000 LAN")
            networkType="LAN"
            ;;
        *)
            networkType="LAN"
            ;;
    esac
fi

############################################

loggedInUser=$(/usr/bin/stat -f%Su /dev/console 2>/dev/null)
if [[ -z "$loggedInUser" || "$loggedInUser" == "root" || "$loggedInUser" == "loginwindow" ]]; then
    echo "<result>No active console user</result>"
    exit 0
fi

userUID=$(/usr/bin/id -u "$loggedInUser" 2>/dev/null)
if [[ -z "$userUID" ]]; then
    echo "<result>Unable to determine UID for $loggedInUser</result>"
    exit 0
fi

userHome=$(/usr/bin/dscl . -read "/Users/$loggedInUser" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}')
if [[ -z "$userHome" ]]; then
    echo "<result>Unable to determine home directory for $loggedInUser</result>"
    exit 0
fi

aadPlist="$userHome/Library/Preferences/com.jamf.management.jamfAAD.plist"
aadID="NotFound"

if [[ -f "$aadPlist" ]]; then
    aadID=$(/usr/bin/defaults read "$aadPlist" have_an_Azure_id 2>/dev/null)
    [[ -z "$aadID" ]] && aadID="0"
fi

if [[ ! -x "$jamfCA" ]]; then
    echo "<result>User: $loggedInUser
Home: $userHome
Captured: $captureTime
Network: $networkType
Status: Jamf Conditional Access binary not found
JamfAAD have_an_Azure_id: $aadID</result>"
    exit 0
fi

ssoStatus=$(runAsUser "$userUID" "$jamfCA" getPSSOStatus 2>/dev/null | /usr/bin/tr -d '()[]"' | /usr/bin/sed -E 's/, /\n/g')

if [[ -z "$ssoStatus" ]]; then
    echo "<result>User: $loggedInUser
Home: $userHome
Captured: $captureTime
Network: $networkType
Status: No getPSSOStatus data returned
JamfAAD have_an_Azure_id: $aadID</result>"
    exit 0
fi

rawStatus=$(printf '%s\n' "$ssoStatus" | /usr/bin/head -n1 | /usr/bin/tr -d '[:space:]')

case "$rawStatus" in
    0) pssoStatusText="pSSO Not Enabled" ;;
    1) pssoStatusText="pSSO Enabled not registered" ;;
    2) pssoStatusText="pSSO Enabled and registered" ;;
    *) pssoStatusText="Unknown pSSO State" ;;
esac

cleanStatus=$(printf '%s\n' "$ssoStatus" | /usr/bin/sed -E 's/(extraDeviceInformation |AnyHashable|primary_registration_metadata_)//g')

tenant_id=$(get_value "$cleanStatus" "tenant_id")
device_id=$(get_value "$cleanStatus" "device_id")
upn=$(get_value "$cleanStatus" "upn")
cloud_host=$(get_value "$cleanStatus" "cloud_host")
full_mode=$(get_value "$cleanStatus" "isSSOExtensionInFullMode")

[[ -z "$tenant_id" ]] && tenant_id="NotFound"
[[ -z "$device_id" ]] && device_id="NotFound"
[[ -z "$upn" ]] && upn="NotFound"
[[ -z "$cloud_host" ]] && cloud_host="NotFound"
[[ -z "$full_mode" ]] && full_mode="NotFound"

if [[ "$rawStatus" == "2" ]]; then
    registrationState="Registered"
elif [[ "$rawStatus" == "1" ]]; then
    registrationState="Not Fully Registered"
else
    registrationState="Not Registered"
fi

echo "<result>User: $loggedInUser
Home: $userHome
Captured: $captureTime
Network: $networkType
Registration: $registrationState
PSSO Status: $rawStatus ($pssoStatusText)
JamfAAD have_an_Azure_id: $aadID
tenant_id: $tenant_id
device_id: $device_id
isSSOExtensionInFullMode: $full_mode
cloud_host: $cloud_host
upn: $upn</result>"
