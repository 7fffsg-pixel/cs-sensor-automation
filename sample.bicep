targetScope = 'subscription'

// ============================================================================
// Parameters (kept close to the original, but secrets are Key Vault URIs only)
// ============================================================================

@description('Operating systems to deploy policies for')
@allowed([
  'linux'
  'windows'
  'both'
])
param operatingSystem string = 'both'

@description('Policy definition name prefix')
param policyDefinitionNamePrefix string = 'CS-Falcon-Policy'

@description('Effect for the policy assignment (DeployIfNotExists, AuditIfNotExists, Disabled)')
@allowed([
  'DeployIfNotExists'
  'AuditIfNotExists'
  'Disabled'
])
param policyEffect string = 'DeployIfNotExists'

@description('Create role assignments for policy managed identities (requires Owner or User Access Administrator role)')
param createRoleAssignments bool = true

@description('Handler version for the CrowdStrike Falcon extension (0.0 lets the platform choose)')
param handlerVersion string = '0.0'

@description('Auto upgrade minor version for the CrowdStrike Falcon extension')
param autoUpgradeMinorVersion bool = true

@description('Enable automatic upgrade for the extension if supported by the publisher')
param enableAutomaticUpgrade bool = true

// CrowdStrike and install parameters (non-secret)
@description('Azure Key Vault name (optional to pass through to the extension if your org uses it internally)')
param azureVaultName string = ''

@description('CrowdStrike Cloud realm (e.g. autodiscover, us-1, us-2, eu-1)')
param cloud string = 'autodiscover'

@description('CrowdStrike Member CID')
param memberCid string = ''

@description('CrowdStrike Sensor Update Policy')
param sensorUpdatePolicy string = 'platform_default'

@description('Disable proxy settings')
param disableProxy bool = false

@description('Proxy host (if using proxy)')
param proxyHost string = ''

@description('Proxy port (if using proxy)')
param proxyPort string = ''

@description('Comma-separated list of tags to pass to the sensor')
param tags string = ''

@description('Windows-only: PAC URL')
param pacUrl string = ''

@description('Windows-only: Disable provisioning wait')
param disableProvisioningWait bool = false

@description('Windows-only: Disable start')
param disableStart bool = false

@description('Windows-only: Provisioning wait time (ms)')
param provisioningWaitTime string = '1200000'

@description('Windows-only: VDI mode')
param vdi bool = false

// Key Vault secret URIs (with version) — ONLY way to provide secrets
@description('Secret URI with version for CrowdStrike client ID (leave empty if not used by your org)')
param kvClientIdSecretUriWithVersion string = ''

@description('Secret URI with version for CrowdStrike client secret (leave empty if not used by your org)')
param kvClientSecretSecretUriWithVersion string = ''

@description('Secret URI with version for CrowdStrike access token (leave empty if not used by your org)')
param kvAccessTokenSecretUriWithVersion string = ''

@description('Secret URI with version for CrowdStrike provisioning token (leave empty if not used by your org)')
param kvProvisioningTokenSecretUriWithVersion string = ''


// ============================================================================
// Variables
// ============================================================================

var operatingSystemLower = toLower(operatingSystem)
// Built-in role used by the original template for remediation (kept for compatibility)
var vmRoleDefinitionId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
var linuxPolicyDefinitionName = '${policyDefinitionNamePrefix}-Linux'
var windowsPolicyDefinitionName = '${policyDefinitionNamePrefix}-Windows'

// ============================================================================
// Policy Definition: Linux (DeployIfNotExists) with drift detection
// ============================================================================
resource linuxPolicyDefinition 'Microsoft.Authorization/policyDefinitions@2020-09-01' = if (operatingSystemLower == 'linux' || operatingSystemLower == 'both') {
  name: linuxPolicyDefinitionName
  properties: {
    displayName: 'Deploy CrowdStrike Falcon sensor on Linux VMs'
    description: 'This policy deploys CrowdStrike Falcon sensor on Linux VMs if not installed, and requires successful provisioning to be compliant.'
    policyType: 'Custom'
    mode: 'Indexed'
    metadata: {
      category: 'Security'
      version: '1.1.0'
    }
    parameters: {
      effect: {
        type: 'String'
        metadata: {
          displayName: 'Effect'
          description: 'Enable or disable the execution of the policy'
        }
        allowedValues: [
          'DeployIfNotExists'
          'AuditIfNotExists'
          'Disabled'
        ]
        defaultValue: 'DeployIfNotExists'
      }
      // Non-secret params
      azureVaultName: {
        type: 'String'
        metadata: {
          displayName: 'Azure Key Vault Name (optional passthrough)'
          description: 'Azure Key Vault name to pass to the extension protected settings (optional).'
        }
        defaultValue: ''
      }
      cloud: {
        type: 'String'
        metadata: {
          displayName: 'CrowdStrike Cloud'
          description: 'CrowdStrike Cloud region'
        }
        defaultValue: 'autodiscover'
      }
      memberCid: {
        type: 'String'
        metadata: {
          displayName: 'Member CID'
          description: 'CrowdStrike Member CID'
        }
        defaultValue: ''
      }
      sensorUpdatePolicy: {
        type: 'String'
        metadata: {
          displayName: 'Sensor Update Policy'
          description: 'CrowdStrike Sensor Update Policy'
        }
        defaultValue: 'platform_default'
      }
      disableProxy: {
        type: 'Boolean'
        metadata: {
          displayName: 'Disable Proxy'
          description: 'Disable proxy settings'
        }
        defaultValue: false
      }
      proxyHost: {
        type: 'String'
        metadata: {
          displayName: 'Proxy Host'
          description: 'Proxy host configuration'
        }
        defaultValue: ''
      }
      proxyPort: {
        type: 'String'
        metadata: {
          displayName: 'Proxy Port'
          description: 'Proxy port configuration'
        }
        defaultValue: ''
      }
      tags: {
        type: 'String'
        metadata: {
          displayName: 'Tags'
          description: 'Comma-separated list of tags'
        }
        defaultValue: ''
      }
      handlerVersion: {
        type: 'String'
        metadata: {
          displayName: 'Handler Version'
          description: 'CrowdStrike Falcon extension handler version'
        }
        defaultValue: '0.0'
      }
      autoUpgradeMinorVersion: {
        type: 'Boolean'
        metadata: {
          displayName: 'Auto Upgrade Minor Version'
          description: 'Auto upgrade minor version for the CrowdStrike Falcon extension'
        }
        defaultValue: true
      }
      enableAutomaticUpgrade: {
        type: 'Boolean'
        metadata: {
          displayName: 'Enable Automatic Upgrade'
          description: 'Enable automatic upgrade if supported by the extension/publisher'
        }
        defaultValue: true
      }

      // Key Vault URIs (with version) for secrets — ONLY input path
      kvClientIdSecretUriWithVersion: {
        type: 'String'
        metadata: {
          displayName: 'KV Client ID Secret URI (with version)'
          description: 'Key Vault secret URI with version for client_id (optional)'
        }
        defaultValue: ''
      }
      kvClientSecretSecretUriWithVersion: {
        type: 'String'
        metadata: {
          displayName: 'KV Client Secret Secret URI (with version)'
          description: 'Key Vault secret URI with version for client_secret (optional)'
        }
        defaultValue: ''
      }
      kvAccessTokenSecretUriWithVersion: {
        type: 'String'
        metadata: {
          displayName: 'KV Access Token Secret URI (with version)'
          description: 'Key Vault secret URI with version for access_token (optional)'
        }
        defaultValue: ''
      }
      kvProvisioningTokenSecretUriWithVersion: {
        type: 'String'
        metadata: {
          displayName: 'KV Provisioning Token Secret URI (with version)'
          description: 'Key Vault secret URI with version for provisioning_token (optional)'
        }
        defaultValue: ''
      }
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
            { message: 'CrowdStrike Falcon Linux extension missing or not successfully provisioned.' }
          ]
          // Drift detection: require successful provisioning and correct extension identity
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Compute/virtualMachines/extensions/name', equals: 'CrowdStrikeFalconSensor' }
              { field: 'Microsoft.Compute/virtualMachines/extensions/type', equals: 'FalconSensorLinux' }
              { field: 'Microsoft.Compute/virtualMachines/extensions/publisher', equals: 'Crowdstrike.Falcon' }
              { field: 'Microsoft.Compute/virtualMachines/extensions/provisioningState', equals: 'Succeeded' }
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
                  azureVaultName: { type: 'string' }
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

                  // Secret URIs with version
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
                      // Secrets are pulled from Key Vault at deploy time via secret URIs
                      protectedSettings: {
                        // Optional passthrough if your org uses azure_vault_name in the extension
                        azure_vault_name: '[parameters(''azureVaultName'')]'
                        // Only inject values resolved from Key Vault; empty strings are ignored by extension
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
                azureVaultName: { value: '[parameters(''azureVaultName'')]' }
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
// Policy Assignment: Linux
// ============================================================================
resource linuxPolicyAssignment 'Microsoft.Authorization/policyAssignments@2020-09-01' = if (operatingSystemLower == 'linux' || operatingSystemLower == 'both') {
  name: 'CS-Falcon-Linux-${take(subscription().subscriptionId, 8)}'
  location: deployment().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    policyDefinitionId: linuxPolicyDefinition.id
    displayName: 'Deploy CrowdStrike Falcon sensor on Linux VMs (Subscription)'
    description: 'This policy ensures CrowdStrike Falcon sensor is installed on all Linux VMs in the subscription'
    parameters: {
      effect: { value: policyEffect }
      azureVaultName: { value: azureVaultName }
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

      kvClientIdSecretUriWithVersion: { value: kvClientIdSecretUriWithVersion }
      kvClientSecretSecretUriWithVersion: { value: kvClientSecretSecretUriWithVersion }
      kvAccessTokenSecretUriWithVersion: { value: kvAccessTokenSecretUriWithVersion }
      kvProvisioningTokenSecretUriWithVersion: { value: kvProvisioningTokenSecretUriWithVersion }
    }
  }
}

// ============================================================================
// Policy Definition: Windows (DeployIfNotExists) with drift detection
// ============================================================================
resource windowsPolicyDefinition 'Microsoft.Authorization/policyDefinitions@2020-09-01' = if (operatingSystemLower == 'windows' || operatingSystemLower == 'both') {
  name: windowsPolicyDefinitionName
  properties: {
    displayName: 'Deploy CrowdStrike Falcon sensor on Windows VMs'
    description: 'This policy deploys CrowdStrike Falcon sensor on Windows VMs if not installed, and requires successful provisioning to be compliant.'
    policyType: 'Custom'
    mode: 'Indexed'
    metadata: {
      category: 'Security'
      version: '1.1.0'
    }
    parameters: {
      effect: {
        type: 'String'
        metadata: {
          displayName: 'Effect'
          description: 'Enable or disable the execution of the policy'
        }
        allowedValues: [
          'DeployIfNotExists'
          'AuditIfNotExists'
          'Disabled'
        ]
        defaultValue: 'DeployIfNotExists'
      }
      // Non-secret params
      azureVaultName: {
        type: 'String'
        metadata: {
          displayName: 'Azure Key Vault Name (optional passthrough)'
          description: 'Azure Key Vault name to pass to the extension protected settings (optional).'
        }
        defaultValue: ''
      }
      cloud: {
        type: 'String'
        metadata: {
          displayName: 'CrowdStrike Cloud'
          description: 'CrowdStrike Cloud region'
        }
        defaultValue: 'autodiscover'
      }
      memberCid: {
        type: 'String'
        metadata: {
          displayName: 'Member CID'
          description: 'CrowdStrike Member CID'
        }
        defaultValue: ''
      }
      sensorUpdatePolicy: {
        type: 'String'
        metadata: {
          displayName: 'Sensor Update Policy'
          description: 'CrowdStrike Sensor Update Policy'
        }
        defaultValue: 'platform_default'
      }
      disableProxy: {
        type: 'Boolean'
        metadata: {
          displayName: 'Disable Proxy'
          description: 'Disable proxy settings'
        }
        defaultValue: false
      }
      proxyHost: {
        type: 'String'
        metadata: {
          displayName: 'Proxy Host'
          description: 'Proxy host configuration'
        }
        defaultValue: ''
      }
      proxyPort: {
        type: 'String'
        metadata: {
          displayName: 'Proxy Port'
          description: 'Proxy port configuration'
        }
        defaultValue: ''
      }
      tags: {
        type: 'String'
        metadata: {
          displayName: 'Tags'
          description: 'Comma-separated list of tags'
        }
        defaultValue: ''
      }
      pacUrl: {
        type: 'String'
        metadata: {
          displayName: 'PAC URL'
          description: 'PAC URL for Windows'
        }
        defaultValue: ''
      }
      disableProvisioningWait: {
        type: 'Boolean'
        metadata: {
          displayName: 'Disable Provisioning Wait'
          description: 'Disable provisioning wait for Windows'
        }
        defaultValue: false
      }
      disableStart: {
        type: 'Boolean'
        metadata: {
          displayName: 'Disable Start'
          description: 'Disable start for Windows'
        }
        defaultValue: false
      }
      provisioningWaitTime: {
        type: 'String'
        metadata: {
          displayName: 'Provisioning Wait Time'
          description: 'Provisioning wait time for Windows'
        }
        defaultValue: '1200000'
      }
      vdi: {
        type: 'Boolean'
        metadata: {
          displayName: 'VDI'
          description: 'VDI setting for Windows'
        }
        defaultValue: false
      }
      handlerVersion: {
        type: 'String'
        metadata: {
          displayName: 'Handler Version'
          description: 'CrowdStrike Falcon extension handler version'
        }
        defaultValue: '0.0'
      }
      autoUpgradeMinorVersion: {
        type: 'Boolean'
        metadata: {
          displayName: 'Auto Upgrade Minor Version'
          description: 'Auto upgrade minor version for the CrowdStrike Falcon extension'
        }
        defaultValue: true
      }
      enableAutomaticUpgrade: {
        type: 'Boolean'
        metadata: {
          displayName: 'Enable Automatic Upgrade'
          description: 'Enable automatic upgrade if supported by the extension/publisher'
        }
        defaultValue: true
      }

      // Key Vault URIs (with version) for secrets — ONLY input path
      kvClientIdSecretUriWithVersion: {
        type: 'String'
        metadata: {
          displayName: 'KV Client ID Secret URI (with version)'
          description: 'Key Vault secret URI with version for client_id (optional)'
        }
        defaultValue: ''
      }
      kvClientSecretSecretUriWithVersion: {
        type: 'String'
        metadata: {
          displayName: 'KV Client Secret Secret URI (with version)'
          description: 'Key Vault secret URI with version for client_secret (optional)'
        }
        defaultValue: ''
      }
      kvAccessTokenSecretUriWithVersion: {
        type: 'String'
        metadata: {
          displayName: 'KV Access Token Secret URI (with version)'
          description: 'Key Vault secret URI with version for access_token (optional)'
        }
        defaultValue: ''
      }
      kvProvisioningTokenSecretUriWithVersion: {
        type: 'String'
        metadata: {
          displayName: 'KV Provisioning Token Secret URI (with version)'
          description: 'Key Vault secret URI with version for provisioning_token (optional)'
        }
        defaultValue: ''
      }
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
            { message: 'CrowdStrike Falcon Windows extension missing or not successfully provisioned.' }
          ]
          // Drift detection: require successful provisioning and correct extension identity
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Compute/virtualMachines/extensions/name', equals: 'CrowdStrikeFalconSensor' }
              { field: 'Microsoft.Compute/virtualMachines/extensions/type', equals: 'FalconSensorWindows' }
              { field: 'Microsoft.Compute/virtualMachines/extensions/publisher', equals: 'Crowdstrike.Falcon' }
              { field: 'Microsoft.Compute/virtualMachines/extensions/provisioningState', equals: 'Succeeded' }
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
                  azureVaultName: { type: 'string' }
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

                  // Secret URIs with version
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
                      // Secrets are pulled from Key Vault at deploy time via secret URIs
                      protectedSettings: {
                        // Optional passthrough if your org uses azure_vault_name in the extension
                        azure_vault_name: '[parameters(''azureVaultName'')]'
                        // Only inject values resolved from Key Vault; empty strings are ignored by extension
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
                azureVaultName: { value: '[parameters(''azureVaultName'')]' }
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
// Policy Assignment: Windows
// ============================================================================
resource windowsPolicyAssignment 'Microsoft.Authorization/policyAssignments@2020-09-01' = if (operatingSystemLower == 'windows' || operatingSystemLower == 'both') {
  name: 'CS-Falcon-Windows-${take(subscription().subscriptionId, 8)}'
  location: deployment().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    policyDefinitionId: windowsPolicyDefinition.id
    displayName: 'Deploy CrowdStrike Falcon sensor on Windows VMs (Subscription)'
    description: 'This policy ensures CrowdStrike Falcon sensor is installed on all Windows VMs in the subscription'
    parameters: {
      effect: { value: policyEffect }
      azureVaultName: { value: azureVaultName }
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

      kvClientIdSecretUriWithVersion: { value: kvClientIdSecretUriWithVersion }
      kvClientSecretSecretUriWithVersion: { value: kvClientSecretSecretUriWithVersion }
      kvAccessTokenSecretUriWithVersion: { value: kvAccessTokenSecretUriWithVersion }
      kvProvisioningTokenSecretUriWithVersion: { value: kvProvisioningTokenSecretUriWithVersion }
    }
  }
}

// ============================================================================
// Role assignments for the policies' managed identities (subscription scope)
// Keep original built-in role to avoid API drift and ensure remediation works
// ============================================================================
resource linuxVmContributorRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (createRoleAssignments && (operatingSystemLower == 'linux' || operatingSystemLower == 'both')) {
  name: guid(linuxPolicyAssignment.id, vmRoleDefinitionId, subscription().id, 'Linux')
  properties: {
    principalId: linuxPolicyAssignment!.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', vmRoleDefinitionId)
    principalType: 'ServicePrincipal'
  }
}

resource windowsVmContributorRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (createRoleAssignments && (operatingSystemLower == 'windows' || operatingSystemLower == 'both')) {
  name: guid(windowsPolicyAssignment.id, vmRoleDefinitionId, subscription().id, 'Windows')
  properties: {
    principalId: windowsPolicyAssignment!.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', vmRoleDefinitionId)
    principalType: 'ServicePrincipal'
  }
}

// ============================================================================
// Outputs
// ============================================================================
output linuxPolicyDefinitionId string = (operatingSystemLower == 'linux' || operatingSystemLower == 'both') ? linuxPolicyDefinition.id : ''
output windowsPolicyDefinitionId string = (operatingSystemLower == 'windows' || operatingSystemLower == 'both') ? windowsPolicyDefinition.id : ''
output linuxPolicyAssignmentId string = (operatingSystemLower == 'linux' || operatingSystemLower == 'both') ? linuxPolicyAssignment.id : ''
output windowsPolicyAssignmentId string = (operatingSystemLower == 'windows' || operatingSystemLower == 'both') ? windowsPolicyAssignment.id : ''
output linuxPolicyPrincipalId string = (operatingSystemLower == 'linux' || operatingSystemLower == 'both') ? linuxPolicyAssignment!.identity.principalId : ''
output windowsPolicyPrincipalId string = (operatingSystemLower == 'windows' || operatingSystemLower == 'both') ? windowsPolicyAssignment!.identity.principalId : ''
output subscriptionId string = subscription().subscriptionId
output subscriptionName string = subscription().displayName
