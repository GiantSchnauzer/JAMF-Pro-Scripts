####################################################################################################
#
# Script Name: Jamf Conditional Access PSSO Information Collector
#
# Description:
# This script collects Jamf Conditional Access and Microsoft Platform SSO information for the
# currently logged in macOS user. It executes Jamf Conditional Access commands in a specific order
# to retrieve version details, Azure AD user association, and Platform SSO registration metadata.
#
# The script gathers the following information:
# • Jamf Conditional Access version
# • Azure AD user association for the logged in macOS account
# • Platform SSO status code
# • Azure AD device metadata including Tenant ID and Device ID
# • Microsoft Enterprise SSO Extension full mode status
# • Azure authentication cloud host
#
# Execution Order:
# 1. Jamf Conditional Access version
# 2. Jamf Conditional Access gatherAADInfo
# 3. Jamf Conditional Access getPSSOStatus
#
# Jamf Pro Usage:
# This script can be used in two scenarios:
#
# 1. Extension Attribute
#    Configure this script as a Jamf Pro Extension Attribute to report Jamf Conditional Access
#    and Platform SSO related values during inventory submission.
#
# 2. Inventory Collection
#    The script collects data when a Jamf inventory update is performed. Inventory updates occur
#    when the command `jamf recon` is executed.
#
# Important Notes:
# • Jamf inventory must be updated using `jamf recon` for Jamf Pro to store the latest EA value.
# • If used as an Extension Attribute, it will run during inventory collection initiated by recon.
# • The script relies on Jamf Conditional Access components being installed on the device.
# • The script retrieves information for the currently logged in console user only.
#
# Author: Anyone
# Created: 2026-03-05
# Version: 1.0
#
# Change Log:
# 2026-03-05  v1.0  Initial version
#
####################################################################################################
