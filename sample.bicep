targetScope = 'subscription'

// ============================================================================
// Parameters
// ============================================================================

@description('Target OS: linux, windows, or both')
@allowed([
  'linux'
  'windows'
  'both'
])
param operatingSystem string = 'both'

@description('Policy effect')
@allowed([
  'DeployIfNotExists'
  'AuditIfNotExists'
  'Disabled'
])
param policyEffect string = 'DeployIfNotExists'

@description('Policy name prefix')
param policyDefinitionNamePrefix string = 'CS-Falcon-Policy'

@description('Location to store policy assignments (Azure requires a location for MI on assignments).')
param assignmentLocation string = 'eastus'

// Extension versioning and updates
@description('Extension handler version. Use 0.0 to let the platform choose.')
param handlerVersion string = '0.0'

@description('autoUpgradeMinorVersion for the extension.')
param autoUpgradeMinorVersion bool = true

@description('enableAutomaticUpgrade for the extension (where supported).')
param enableAutomaticUpgrade bool = true

// Non-secret configuration
@description('CrowdStrike cloud realm (e.g., autodiscover, us-1, us-2, eu-1).')
param cloud string = 'autodiscover'

@description('CrowdStrike Member CID.')
param memberCid string = ''

@description('CrowdStrike Sensor Update Policy.')
param sensorUpdatePolicy string = 'platform_default'

@description('Disable proxy.')
param disableProxy bool = false

@description('Proxy host.')
param proxyHost string = ''

@description('Proxy port.')
param proxyPort string = ''

@description('Comma-separated tags to send to the sensor.')
param tags string = ''

// Windows-only
@description('Windows: PAC URL.')
param pacUrl string = ''

@description('Windows: Disable provisioning wait.')
param disableProvisioningWait bool = false

@description('Windows: Disable service start after install.')
param disableStart bool = false

@description('Windows: Provisioning wait time (ms).')
param provisioningWaitTime string = '1200000'

@description('Windows: VDI flag.')
param vdi bool = false

// Key Vault secret URIs (with version) — ONLY allowed secret input path
@description('Secret URI with version for CrowdStrike client_id (optional).')
param kvClientIdSecretUriWithVersion string = ''

@description('Secret URI with version for CrowdStrike client_secret (optional).')
param kvClientSecretSecretUriWithVersion string = ''

@description('Secret URI with version for CrowdStrike access_token (optional).')
param kvAccessTokenSecretUriWithVersion string = ''

@description('Secret URI with version for CrowdStrike provisioning_token (optional).')
param kvProvisioningTokenSecretUriWithVersion string = ''

// Optional: pass vault name if your org’s extension config uses it internally
@description('Azure Key Vault name (optional passthrough to protectedSettings).')
param azureVaultName string = ''


// ============================================================================
// Variables
// ============================================================================
var osLower = toLower(operatingSystem)
var linuxPolicyDefinitionName = '${policyDefinitionNamePrefix}-Linux'
var windowsPolicyDefinitionName = '${policyDefinitionNamePrefix}-Windows'

// Built-in Owner role for remediation in the original template (kept for compatibility)
// If you prefer least-privilege, replace with a custom role and roleAssignment.
var vmRoleDefinitionId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'

// ============================================================================
// Policy Definition: Linux
// ============================================================================
resource linuxPolicyDefinition 'Microsoft.Authorization/policyDefinitions@2020-09-01' = if (osLower == 'linux' || osLower == 'both') {
  name: linuxPolicyDefinitionName
  properties: {
    displayName: 'Deploy CrowdStrike Falcon sensor on Linux VMs'
    description: 'Deploys the CrowdStrike Falcon Linux extension when missing.'
    policyType: 'Custom'
    mode: 'Indexed'
    metadata: {
      category: 'Security'
      version: '1.0.0'
    }
    parameters: {
      effect: {
        type: 'String'
        metadata: {
          displayName: 'Effect'
          description: 'Enable or disable the policy.'
        }
        allowedValues: [
          'DeployIfNotExists'
          'AuditIfNotExists'
          'Disabled'
        ]
        defaultValue: 'DeployIfNotExists'
      }
      cloud: { type: 'String' }
      memberCid: { type: 'String' }
      sensorUpdatePolicy: { type: 'String' }
      disableProxy: { type: 'Boolean' }
      proxyHost: { type: 'String' }
      proxyPort: { type: 'String' }
      tags: { type: 'String' }
      handlerVersion: { type: 'String' }
      autoUpgradeMinorVersion: { type: 'Boolean' }
      enableAutomaticUpgrade: { type: 'Boolean' }
      azureVaultName: { type: 'String' }

      // Secret URIs with version (no direct secrets)
      kvClientIdSecretUriWithVersion: { type: 'String' }
      kvClientSecretSecretUriWithVersion: { type: 'String' }
      kvAccessTokenSecretUriWithVersion: { type: 'String' }
      kvProvisioningTokenSecretUriWithVersion: { type: 'String' }
    }
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.Compute/virtualMachines' }
          { field: 'Microsoft.Compute/virtualMachines/osProfile.linuxConfiguration', exists: 'true' }
        ]
      }
      then: {
        effect: '[parameters(''effect'')]'
        details: {
          type: 'Microsoft.Compute/virtualMachines/extensions'
          roleDefinitionIds: [
            subscriptionResourceId('Microsoft.Authorization/roleDefinitions', vmRoleDefinitionId)
          ]
          nonComplianceMessages: [
            { message: 'CrowdStrike Falcon Linux extension is missing.' }
          ]
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Compute/virtualMachines/extensions/name', equals: 'CrowdStrikeFalconSensor' }
              { field: 'Microsoft.Compute/virtualMachines/extensions/type', equals: 'FalconSensorLinux' }
              { field: 'Microsoft.Compute/virtualMachines/extensions/publisher', equals: 'Crowdstrike.Falcon' }
            ]
          }
          deployment: {
            properties: {
              mode: 'incremental'
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  vmName: { type: 'string' }
                  location: { type: 'string' }

                  cloud: { type: 'string' }
                  memberCid: { type: 'string' }
                  sensorUpdatePolicy: { type: 'string' }
                  disableProxy: { type: 'bool' }
                  proxyHost: { type: 'string' }
                  proxyPort: { type: 'string' }
                  tags: { type: 'string' }

                  handlerVersion: { type: 'string' }
                  autoUpgradeMinorVersion: { type: 'bool' }
                  enableAutomaticUpgrade: { type: 'bool' }

                  azureVaultName: { type: 'string' }

                  // Secret URIs
                  kvClientIdSecretUriWithVersion: { type: 'string' }
                  kvClientSecretSecretUriWithVersion: { type: 'string' }
                  kvAccessTokenSecretUriWithVersion: { type: 'string' }
                  kvProvisioningTokenSecretUriWithVersion: { type: 'string' }
                }
                resources: [
                  {
                    name: '[concat(parameters(''vmName''), ''/CrowdStrikeFalconSensor'')]'
                    type: 'Microsoft.Compute/virtualMachines/extensions'
                    location: '[parameters(''location'')]'
                    apiVersion: '2021-07-01'
                    properties: {
                      publisher: 'Crowdstrike.Falcon'
                      type: 'FalconSensorLinux'
                      typeHandlerVersion: '[parameters(''handlerVersion'')]'
                      autoUpgradeMinorVersion: '[parameters(''autoUpgradeMinorVersion'')]'
                      enableAutomaticUpgrade: '[parameters(''enableAutomaticUpgrade'')]'
                      settings: {
                        cloud: '[parameters(''cloud'')]'
                        member_cid: '[parameters(''memberCid'')]'
                        sensor_update_policy: '[parameters(''sensorUpdatePolicy'')]'
                        disable_proxy: '[parameters(''disableProxy'')]'
                        proxy_host: '[parameters(''proxyHost'')]'
                        proxy_port: '[parameters(''proxyPort'')]'
                        tags: '[parameters(''tags'')]'
                      }
                      protectedSettings: {
                        // Optional passthrough (if your org uses it)
                        azure_vault_name: '[parameters(''azureVaultName'')]'
                        // Resolve values from Key Vault via secret URIs (with version). Empty strings resolve to empty.
                        client_id: "[if(empty(parameters('kvClientIdSecretUriWithVersion')), '', reference(parameters('kvClientIdSecretUriWithVersion'), '2015-06-01').value)]"
                        client_secret: "[if(empty(parameters('kvClientSecretSecretUriWithVersion')), '', reference(parameters('kvClientSecretSecretUriWithVersion'), '2015-06-01').value)]"
                        access_token: "[if(empty(parameters('kvAccessTokenSecretUriWithVersion')), '', reference(parameters('kvAccessTokenSecretUriWithVersion'), '2015-06-01').value)]"
                        provisioning_token: "[if(empty(parameters('kvProvisioningTokenSecretUriWithVersion')), '', reference(parameters('kvProvisioningTokenSecretUriWithVersion'), '2015-06-01').value)]"
                      }
                    }
                  }
                ]
              }
              parameters: {
                vmName: { value: '[field(''name'')]' }
                location: { value: '[field(''location'')]' }

                cloud: { value: '[parameters(''cloud'')]' }
                memberCid: { value: '[parameters(''memberCid'')]' }
                sensorUpdatePolicy: { value: '[parameters(''sensorUpdatePolicy'')]' }
                disableProxy: { value: '[parameters(''disableProxy'')]' }
                proxyHost: { value: '[parameters(''proxyHost'')]' }
                proxyPort: { value: '[parameters(''proxyPort'')]' }
                tags: { value: '[parameters(''tags'')]' }

                handlerVersion: { value: '[parameters(''handlerVersion'')]' }
                autoUpgradeMinorVersion: { value: '[parameters(''autoUpgradeMinorVersion'')]' }
                enableAutomaticUpgrade: { value: '[parameters(''enableAutomaticUpgrade'')]' }

                azureVaultName: { value: '[parameters(''azureVaultName'')]' }

                kvClientIdSecretUriWithVersion: { value: '[parameters(''kvClientIdSecretUriWithVersion'')]' }
                kvClientSecretSecretUriWithVersion: { value: '[parameters(''kvClientSecretSecretUriWithVersion'')]' }
                kvAccessTokenSecretUriWithVersion: { value: '[parameters(''kvAccessTokenSecretUriWithVersion'')]' }
                kvProvisioningTokenSecretUriWithVersion: { value: '[parameters(''kvProvisioningTokenSecretUriWithVersion'')]' }
              }
            }
          }
        }
      }
    }
  }
}

// ============================================================================
// Policy Definition: Windows
// ============================================================================
resource windowsPolicyDefinition 'Microsoft.Authorization/policyDefinitions@2020-09-01' = if (osLower == 'windows' || osLower == 'both') {
  name: windowsPolicyDefinitionName
  properties: {
    displayName: 'Deploy CrowdStrike Falcon sensor on Windows VMs'
    description: 'Deploys the CrowdStrike Falcon Windows extension when missing.'
    policyType: 'Custom'
    mode: 'Indexed'
    metadata: {
      category: 'Security'
      version: '1.0.0'
    }
    parameters: {
      effect: {
        type: 'String'
        metadata: {
          displayName: 'Effect'
          description: 'Enable or disable the policy.'
        }
        allowedValues: [
          'DeployIfNotExists'
          'AuditIfNotExists'
          'Disabled'
        ]
        defaultValue: 'DeployIfNotExists'
      }
      cloud: { type: 'String' }
      memberCid: { type: 'String' }
      sensorUpdatePolicy: { type: 'String' }
      disableProxy: { type: 'Boolean' }
      proxyHost: { type: 'String' }
      proxyPort: { type: 'String' }
      tags: { type: 'String' }
      pacUrl: { type: 'String' }
      disableProvisioningWait: { type: 'Boolean' }
      disableStart: { type: 'Boolean' }
      provisioningWaitTime: { type: 'String' }
      vdi: { type: 'Boolean' }
      handlerVersion: { type: 'String' }
      autoUpgradeMinorVersion: { type: 'Boolean' }
      enableAutomaticUpgrade: { type: 'Boolean' }
      azureVaultName: { type: 'String' }

      // Secret URIs with version (no direct secrets)
      kvClientIdSecretUriWithVersion: { type: 'String' }
      kvClientSecretSecretUriWithVersion: { type: 'String' }
      kvAccessTokenSecretUriWithVersion: { type: 'String' }
      kvProvisioningTokenSecretUriWithVersion: { type: 'String' }
    }
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.Compute/virtualMachines' }
          { field: 'Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration', exists: 'true' }
        ]
      }
      then: {
        effect: '[parameters(''effect'')]'
        details: {
          type: 'Microsoft.Compute/virtualMachines/extensions'
          roleDefinitionIds: [
            subscriptionResourceId('Microsoft.Authorization/roleDefinitions', vmRoleDefinitionId)
          ]
          nonComplianceMessages: [
            { message: 'CrowdStrike Falcon Windows extension is missing.' }
          ]
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Compute/virtualMachines/extensions/name', equals: 'CrowdStrikeFalconSensor' }
              { field: 'Microsoft.Compute/virtualMachines/extensions/type', equals: 'FalconSensorWindows' }
              { field: 'Microsoft.Compute/virtualMachines/extensions/publisher', equals: 'Crowdstrike.Falcon' }
            ]
          }
          deployment: {
            properties: {
              mode: 'incremental'
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  vmName: { type: 'string' }
                  location: { type: 'string' }

                  cloud: { type: 'string' }
                  memberCid: { type: 'string' }
                  sensorUpdatePolicy: { type: 'string' }
                  disableProxy: { type: 'bool' }
                  proxyHost: { type: 'string' }
                  proxyPort: { type: 'string' }
                  tags: { type: 'string' }
                  pacUrl: { type: 'string' }
                  disableProvisioningWait: { type: 'bool' }
                  disableStart: { type: 'bool' }
                  provisioningWaitTime: { type: 'string' }
                  vdi: { type: 'bool' }

                  handlerVersion: { type: 'string' }
                  autoUpgradeMinorVersion: { type: 'bool' }
                  enableAutomaticUpgrade: { type: 'bool' }

                  azureVaultName: { type: 'string' }

                  // Secret URIs
                  kvClientIdSecretUriWithVersion: { type: 'string' }
                  kvClientSecretSecretUriWithVersion: { type: 'string' }
                  kvAccessTokenSecretUriWithVersion: { type: 'string' }
                  kvProvisioningTokenSecretUriWithVersion: { type: 'string' }
                }
                resources: [
                  {
                    name: '[concat(parameters(''vmName''), ''/CrowdStrikeFalconSensor'')]'
                    type: 'Microsoft.Compute/virtualMachines/extensions'
                    location: '[parameters(''location'')]'
                    apiVersion: '2021-07-01'
                    properties: {
                      publisher: 'Crowdstrike.Falcon'
                      type: 'FalconSensorWindows'
                      typeHandlerVersion: '[parameters(''handlerVersion'')]'
                      autoUpgradeMinorVersion: '[parameters(''autoUpgradeMinorVersion'')]'
                      enableAutomaticUpgrade: '[parameters(''enableAutomaticUpgrade'')]'
                      settings: {
                        cloud: '[parameters(''cloud'')]'
                        member_cid: '[parameters(''memberCid'')]'
                        sensor_update_policy: '[parameters(''sensorUpdatePolicy'')]'
                        disable_proxy: '[parameters(''disableProxy'')]'
                        proxy_host: '[parameters(''proxyHost'')]'
                        proxy_port: '[parameters(''proxyPort'')]'
                        tags: '[parameters(''tags'')]'
                        pac_url: '[parameters(''pacUrl'')]'
                        disable_provisioning_wait: '[parameters(''disableProvisioningWait'')]'
                        disable_start: '[parameters(''disableStart'')]'
                        provisioning_wait_time: '[parameters(''provisioningWaitTime'')]'
                        vdi: '[parameters(''vdi'')]'
                      }
                      protectedSettings: {
                        // Optional passthrough (if your org uses it)
                        azure_vault_name: '[parameters(''azureVaultName'')]'
                        // Resolve values from Key Vault via secret URIs (with version). Empty strings resolve to empty.
                        client_id: "[if(empty(parameters('kvClientIdSecretUriWithVersion')), '', reference(parameters('kvClientIdSecretUriWithVersion'), '2015-06-01').value)]"
                        client_secret: "[if(empty(parameters('kvClientSecretSecretUriWithVersion')), '', reference(parameters('kvClientSecretSecretUriWithVersion'), '2015-06-01').value)]"
                        access_token: "[if(empty(parameters('kvAccessTokenSecretUriWithVersion')), '', reference(parameters('kvAccessTokenSecretUriWithVersion'), '2015-06-01').value)]"
                        provisioning_token: "[if(empty(parameters('kvProvisioningTokenSecretUriWithVersion')), '', reference(parameters('kvProvisioningTokenSecretUriWithVersion'), '2015-06-01').value)]"
                      }
                    }
                  }
                ]
              }
              parameters: {
                vmName: { value: '[field(''name'')]' }
                location: { value: '[field(''location'')]' }

                cloud: { value: '[parameters(''cloud'')]' }
                memberCid: { value: '[parameters(''memberCid'')]' }
                sensorUpdatePolicy: { value: '[parameters(''sensorUpdatePolicy'')]' }
                disableProxy: { value: '[parameters(''disableProxy'')]' }
                proxyHost: { value: '[parameters(''proxyHost'')]' }
                proxyPort: { value: '[parameters(''proxyPort'')]' }
                tags: { value: '[parameters(''tags'')]' }
                pacUrl: { value: '[parameters(''pacUrl'')]' }
                disableProvisioningWait: { value: '[parameters(''disableProvisioningWait'')]' }
                disableStart: { value: '[parameters(''disableStart'')]' }
                provisioningWaitTime: { value: '[parameters(''provisioningWaitTime'')]' }
                vdi: { value: '[parameters(''vdi'')]' }

                handlerVersion: { value: '[parameters(''handlerVersion'')]' }
                autoUpgradeMinorVersion: { value: '[parameters(''autoUpgradeMinorVersion'')]' }
                enableAutomaticUpgrade: { value: '[parameters(''enableAutomaticUpgrade'')]' }

                azureVaultName: { value: '[parameters(''azureVaultName'')]' }

                kvClientIdSecretUriWithVersion: { value: '[parameters(''kvClientIdSecretUriWithVersion'')]' }
                kvClientSecretSecretUriWithVersion: { value: '[parameters(''kvClientSecretSecretUriWithVersion'')]' }
                kvAccessTokenSecretUriWithVersion: { value: '[parameters(''kvAccessTokenSecretUriWithVersion'')]' }
                kvProvisioningTokenSecretUriWithVersion: { value: '[parameters(''kvProvisioningTokenSecretUriWithVersion'')]' }
              }
            }
          }
        }
      }
    }
  }
}

// ============================================================================
// Policy Assignments (system-assigned identity for remediation)
// ============================================================================

resource linuxPolicyAssignment 'Microsoft.Authorization/policyAssignments@2020-09-01' = if (osLower == 'linux' || osLower == 'both') {
  name: 'CS-Falcon-Linux-${take(subscription().subscriptionId, 8)}'
  location: assignmentLocation
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: 'Deploy CrowdStrike Falcon sensor on Linux VMs (Subscription)'
    description: 'Ensures CrowdStrike Falcon is installed on all Linux VMs in this subscription.'
    policyDefinitionId: linuxPolicyDefinition.id
    parameters: {
      effect: { value: policyEffect }
      cloud: { value: cloud }
      memberCid: { value: memberCid }
      sensorUpdatePolicy: { value: sensorUpdatePolicy }
      disableProxy: { value: disableProxy }
      proxyHost: { value: proxyHost }
      proxyPort: { value: proxyPort }
      tags: { value: tags }
      handlerVersion: { value: handlerVersion }
      autoUpgradeMinorVersion: { value: autoUpgradeMinorVersion }
      enableAutomaticUpgrade: { value: enableAutomaticUpgrade }
      azureVaultName: { value: azureVaultName }

      kvClientIdSecretUriWithVersion: { value: kvClientIdSecretUriWithVersion }
      kvClientSecretSecretUriWithVersion: { value: kvClientSecretSecretUriWithVersion }
      kvAccessTokenSecretUriWithVersion: { value: kvAccessTokenSecretUriWithVersion }
      kvProvisioningTokenSecretUriWithVersion: { value: kvProvisioningTokenSecretUriWithVersion }
    }
  }
}

resource windowsPolicyAssignment 'Microsoft.Authorization/policyAssignments@2020-09-01' = if (osLower == 'windows' || osLower == 'both') {
  name: 'CS-Falcon-Windows-${take(subscription().subscriptionId, 8)}'
  location: assignmentLocation
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: 'Deploy CrowdStrike Falcon sensor on Windows VMs (Subscription)'
    description: 'Ensures CrowdStrike Falcon is installed on all Windows VMs in this subscription.'
    policyDefinitionId: windowsPolicyDefinition.id
    parameters: {
      effect: { value: policyEffect }
      cloud: { value: cloud }
      memberCid: { value: memberCid }
      sensorUpdatePolicy: { value: sensorUpdatePolicy }
      disableProxy: { value: disableProxy }
      proxyHost: { value: proxyHost }
      proxyPort: { value: proxyPort }
      tags: { value: tags }
      pacUrl: { value: pacUrl }
      disableProvisioningWait: { value: disableProvisioningWait }
      disableStart: { value: disableStart }
      provisioningWaitTime: { value: provisioningWaitTime }
      vdi: { value: vdi }
      handlerVersion: { value: handlerVersion }
      autoUpgradeMinorVersion: { value: autoUpgradeMinorVersion }
      enableAutomaticUpgrade: { value: enableAutomaticUpgrade }
      azureVaultName: { value: azureVaultName }

      kvClientIdSecretUriWithVersion: { value: kvClientIdSecretUriWithVersion }
      kvClientSecretSecretUriWithVersion: { value: kvClientSecretSecretUriWithVersion }
      kvAccessTokenSecretUriWithVersion: { value: kvAccessTokenSecretUriWithVersion }
      kvProvisioningTokenSecretUriWithVersion: { value: kvProvisioningTokenSecretUriWithVersion }
    }
  }
}

// ============================================================================
// Outputs
// ============================================================================
output linuxPolicyDefinitionId string = (osLower == 'linux' || osLower == 'both') ? linuxPolicyDefinition.id : ''
output windowsPolicyDefinitionId string = (osLower == 'windows' || osLower == 'both') ? windowsPolicyDefinition.id : ''
output linuxPolicyAssignmentId string = (osLower == 'linux' || osLower == 'both') ? linuxPolicyAssignment.id : ''
output windowsPolicyAssignmentId string = (osLower == 'windows' || osLower == 'both') ? windowsPolicyAssignment.id : ''
