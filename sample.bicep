// ============================================================================
// CrowdStrike Falcon — Auto-install + Drift-Heal Policy (VM + optional VMSS)
// Benjamin-ready: robust, scalable, secure (no raw secrets), with auto-updates.
// ============================================================================

targetScope = 'subscription'

// ---------------------------
// Parameters
// ---------------------------
@description('Management group or subscription-level category for the policies.')
param policyCategory string = 'Security Center'

@description('Initiative (policy set) display name.')
param initiativeDisplayName string = 'CrowdStrike Falcon — Auto-install + Drift-heal (VM + optional VMSS)'

@description('Deploy VMSS policies too.')
param deployVmssPolicies bool = true

@description('Exemption tag to skip enforcement on specific resources.')
param exemptionTagKey string = 'csfalcon_exempt'

@description('Exemption tag value to skip enforcement.')
param exemptionTagValue string = 'true'

// Sensor config (non-secret)
@description('CrowdStrike cloud realm, e.g. us-1, us-2, eu-1.')
param cloud string = 'us-1'

@description('CrowdStrike Customer ID (CID).')
param memberCid string

@description('Sensor update policy, if used by your org (string). Leave empty if unused.')
param sensorUpdatePolicy string = ''

@description('Disable proxy (true/false).')
param disableProxy bool = true

@description('Proxy host if using proxy.')
param proxyHost string = ''

@description('Proxy port as string if using proxy.')
param proxyPort string = ''

@description('Optional tag payload for Falcon (string).')
param csTags string = ''

// Windows-only config
@description('Windows PAC URL if required.')
param pacUrl string = ''

@description('Disable provisioning wait (Windows only).')
param disableProvisioningWait bool = false

@description('Disable service start after install (Windows only).')
param disableStart bool = false

@description('Provisioning wait time (Windows only).')
param provisioningWaitTime string = '300'

@description('VDI mode flag (Windows only).')
param vdi bool = false

// Extension versioning and update preferences
@description('Type handler version. Use empty to let platform choose.')
param handlerVersion string = ''

@description('autoUpgradeMinorVersion on the extension.')
param autoUpgradeMinorVersion bool = true

@description('enableAutomaticUpgrade on the extension (where supported).')
param enableAutomaticUpgrade bool = true

// Secret handling
@description('Use Key Vault reference-style passing (preferred). If false, you must provide direct protected values below.')
param useKeyVaultRefs bool = true

@description('Azure Key Vault name that contains CrowdStrike secrets (when useKeyVaultRefs=true).')
param azureVaultName string = ''

@description('Secret name for CrowdStrike client ID (if needed by your org).')
param kvSecretNameClientId string = 'cs-client-id'

@description('Secret name for CrowdStrike client secret (if needed by your org).')
param kvSecretNameClientSecret string = 'cs-client-secret'

@description('Secret name for provisioning token (if needed by your org).')
param kvSecretNameProvisioningToken string = 'cs-prov-token'

// Optional direct protected values (only if useKeyVaultRefs=false)
@secure()
@description('Direct client ID (NOT recommended). Used only if useKeyVaultRefs=false.')
param directClientId string = ''

@secure()
@description('Direct client secret (NOT recommended). Used only if useKeyVaultRefs=false.')
param directClientSecret string = ''

@secure()
@description('Direct provisioning token (NOT recommended). Used only if useKeyVaultRefs=false.')
param directProvisioningToken string = ''

// ---------------------------
// Constants
// ---------------------------
var publisher = 'CrowdStrike.Falcon'
var windowsType = 'FalconSensorWindows'
var linuxType = 'FalconSensorLinux'
var extensionResName = 'CrowdStrikeFalconSensor'

// ---------------------------
// Custom role for remediation (least-privilege)
// ---------------------------
@description('Display name for custom role used by remediation.')
param remediationRoleName string = 'VM & VMSS Extension Operator (Scoped)'

@description('Custom role guid (roleDefinition) to ensure idempotency. Provide a stable GUID.')
param remediationRoleGuid string

resource customRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: remediationRoleGuid
  properties: {
    roleName: remediationRoleName
    description: 'Allows management of VM and VMSS extensions and read of target resources for remediation.'
    type: 'CustomRole'
    assignableScopes: [
      subscription().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.Compute/virtualMachines/read'
          'Microsoft.Compute/virtualMachines/extensions/*'
          'Microsoft.Compute/virtualMachineScaleSets/read'
          'Microsoft.Compute/virtualMachineScaleSets/extensions/*'
          'Microsoft.Resources/subscriptions/resourceGroups/read'
          'Microsoft.Compute/locations/operations/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

// ---------------------------
// Policy Definitions
// ---------------------------

@description('Policy: DeployIfNotExists — Ensure CrowdStrike extension on Windows VMs with drift detection.')
resource polWin 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: 'csfalcon-deploy-windows-vm'
  properties: {
    policyType: 'Custom'
    mode: 'All'
    displayName: 'CrowdStrike Falcon — Windows VM extension installed and healthy'
    description: 'Ensures the CrowdStrike Falcon Windows extension is installed and successfully provisioned. Auto-remediates if missing or failed.'
    metadata: {
      category: policyCategory
      version: '1.0.0'
    }
    parameters: policyCommonParams()
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.Compute/virtualMachines' }
          { field: 'tags[${exemptionTagKey}]', notEquals: exemptionTagValue }
          { field: 'Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration', exists: 'true' }
        ]
      }
      then: {
        effect: '[parameters(''effect'')]'
        details: {
          type: 'Microsoft.Compute/virtualMachines/extensions'
          roleDefinitionIds: [
            customRole.id
          ]
          nonComplianceMessages: [
            {
              message: 'CrowdStrike Falcon Windows extension missing or not successfully provisioned.'
            }
          ]
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Compute/virtualMachines/extensions/name', equals: extensionResName }
              { field: 'Microsoft.Compute/virtualMachines/extensions/publisher', equals: publisher }
              { field: 'Microsoft.Compute/virtualMachines/extensions/type', equals: windowsType }
              { field: 'Microsoft.Compute/virtualMachines/extensions/provisioningState', equals: 'Succeeded' }
            ]
          }
          deployment: {
            properties: {
              mode: 'incremental'
              template: extensionDeploymentTemplate(true)
              parameters: extensionDeploymentParameters(true)
            }
          }
        }
      }
    }
  }
}

@description('Policy: DeployIfNotExists — Ensure CrowdStrike extension on Linux VMs with drift detection.')
resource polLin 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: 'csfalcon-deploy-linux-vm'
  properties: {
    policyType: 'Custom'
    mode: 'All'
    displayName: 'CrowdStrike Falcon — Linux VM extension installed and healthy'
    description: 'Ensures the CrowdStrike Falcon Linux extension is installed and successfully provisioned. Auto-remediates if missing or failed.'
    metadata: {
      category: policyCategory
      version: '1.0.0'
    }
    parameters: policyCommonParams()
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.Compute/virtualMachines' }
          { field: 'tags[${exemptionTagKey}]', notEquals: exemptionTagValue }
          // OS check for Linux
          { field: 'Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType', equals: 'Linux' }
        ]
      }
      then: {
        effect: '[parameters(''effect'')]'
        details: {
          type: 'Microsoft.Compute/virtualMachines/extensions'
          roleDefinitionIds: [
            customRole.id
          ]
          nonComplianceMessages: [
            {
              message: 'CrowdStrike Falcon Linux extension missing or not successfully provisioned.'
            }
          ]
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Compute/virtualMachines/extensions/name', equals: extensionResName }
              { field: 'Microsoft.Compute/virtualMachines/extensions/publisher', equals: publisher }
              { field: 'Microsoft.Compute/virtualMachines/extensions/type', equals: linuxType }
              { field: 'Microsoft.Compute/virtualMachines/extensions/provisioningState', equals: 'Succeeded' }
            ]
          }
          deployment: {
            properties: {
              mode: 'incremental'
              template: extensionDeploymentTemplate(false)
              parameters: extensionDeploymentParameters(false)
            }
          }
        }
      }
    }
  }
}

// Optional VMSS counterparts
@description('Policy: DeployIfNotExists — Ensure CrowdStrike extension on Windows VMSS with drift detection.')
resource polVmssWin 'Microsoft.Authorization/policyDefinitions@2021-06-01' = if (deployVmssPolicies) {
  name: 'csfalcon-deploy-windows-vmss'
  properties: {
    policyType: 'Custom'
    mode: 'All'
    displayName: 'CrowdStrike Falcon — Windows VMSS extension installed and healthy'
    description: 'Ensures the CrowdStrike Falcon Windows extension is installed on VMSS and successfully provisioned. Auto-remediates if missing or failed.'
    metadata: {
      category: policyCategory
      version: '1.0.0'
    }
    parameters: policyCommonParams()
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.Compute/virtualMachineScaleSets' }
          { field: 'tags[${exemptionTagKey}]', notEquals: exemptionTagValue }
        ]
      }
      then: {
        effect: '[parameters(''effect'')]'
        details: {
          type: 'Microsoft.Compute/virtualMachineScaleSets/extensions'
          roleDefinitionIds: [
            customRole.id
          ]
          nonComplianceMessages: [
            {
              message: 'CrowdStrike Falcon Windows extension missing or not successfully provisioned on VMSS.'
            }
          ]
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/name', equals: extensionResName }
              { field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/publisher', equals: publisher }
              { field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/type', equals: windowsType }
              { field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/provisioningState', equals: 'Succeeded' }
            ]
          }
          deployment: {
            properties: {
              mode: 'incremental'
              template: extensionDeploymentTemplateVmss(true)
              parameters: extensionDeploymentParametersVmss(true)
            }
          }
        }
      }
    }
  }
}

@description('Policy: DeployIfNotExists — Ensure CrowdStrike extension on Linux VMSS with drift detection.')
resource polVmssLin 'Microsoft.Authorization/policyDefinitions@2021-06-01' = if (deployVmssPolicies) {
  name: 'csfalcon-deploy-linux-vmss'
  properties: {
    policyType: 'Custom'
    mode: 'All'
    displayName: 'CrowdStrike Falcon — Linux VMSS extension installed and healthy'
    description: 'Ensures the CrowdStrike Falcon Linux extension is installed on VMSS and successfully provisioned. Auto-remediates if missing or failed.'
    metadata: {
      category: policyCategory
      version: '1.0.0'
    }
    parameters: policyCommonParams()
    policyRule: {
      if: {
        allOf: [
          { field: 'type', equals: 'Microsoft.Compute/virtualMachineScaleSets' }
          { field: 'tags[${exemptionTagKey}]', notEquals: exemptionTagValue }
        ]
      }
      then: {
        effect: '[parameters(''effect'')]'
        details: {
          type: 'Microsoft.Compute/virtualMachineScaleSets/extensions'
          roleDefinitionIds: [
            customRole.id
          ]
          nonComplianceMessages: [
            {
              message: 'CrowdStrike Falcon Linux extension missing or not successfully provisioned on VMSS.'
            }
          ]
          existenceCondition: {
            allOf: [
              { field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/name', equals: extensionResName }
              { field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/publisher', equals: publisher }
              { field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/type', equals: linuxType }
              { field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/provisioningState', equals: 'Succeeded' }
            ]
          }
          deployment: {
            properties: {
              mode: 'incremental'
              template: extensionDeploymentTemplateVmss(false)
              parameters: extensionDeploymentParametersVmss(false)
            }
          }
        }
      }
    }
  }
}

// ---------------------------
// Initiative (Policy Set)
// ---------------------------
resource initiative 'Microsoft.Authorization/policySetDefinitions@2021-06-01' = {
  name: 'csfalcon-initiative'
  properties: {
    policyType: 'Custom'
    displayName: initiativeDisplayName
    description: 'Auto-install and drift-heal CrowdStrike Falcon across Windows/Linux VMs (and optional VMSS).'
    metadata: {
      category: policyCategory
      version: '1.0.0'
    }
    parameters: policyCommonParams()
    policyDefinitions: [
      {
        policyDefinitionId: polWin.id
        parameters: policySetParamBindings()
      }
      {
        policyDefinitionId: polLin.id
        parameters: policySetParamBindings()
      }
      if (deployVmssPolicies) {
        policyDefinitionId: polVmssWin.id
        parameters: policySetParamBindings()
      }
      if (deployVmssPolicies) {
        policyDefinitionId: polVmssLin.id
        parameters: policySetParamBindings()
      }
    ]
  }
}

// ---------------------------
// Assignment (with system-assigned identity for remediation)
// ---------------------------
@description('Assignment display name.')
param assignmentDisplayName string = 'Assign: CrowdStrike Falcon — Auto-install + Drift-heal'

resource assignment 'Microsoft.Authorization/policyAssignments@2022-06-01' = {
  name: 'assign-csfalcon-initiative'
  properties: {
    displayName: assignmentDisplayName
    policyDefinitionId: initiative.id
    enforcementMode: 'Default'
    parameters: {
      effect: { value: 'DeployIfNotExists' }
      exemptionTagKey: { value: exemptionTagKey }
      exemptionTagValue: { value: exemptionTagValue }
      cloud: { value: cloud }
      memberCid: { value: memberCid }
      sensorUpdatePolicy: { value: sensorUpdatePolicy }
      disableProxy: { value: disableProxy }
      proxyHost: { value: proxyHost }
      proxyPort: { value: proxyPort }
      csTags: { value: csTags }
      pacUrl: { value: pacUrl }
      disableProvisioningWait: { value: disableProvisioningWait }
      disableStart: { value: disableStart }
      provisioningWaitTime: { value: provisioningWaitTime }
      vdi: { value: vdi }
      handlerVersion: { value: handlerVersion }
      autoUpgradeMinorVersion: { value: autoUpgradeMinorVersion }
      enableAutomaticUpgrade: { value: enableAutomaticUpgrade }
      useKeyVaultRefs: { value: useKeyVaultRefs }
      azureVaultName: { value: azureVaultName }
      kvSecretNameClientId: { value: kvSecretNameClientId }
      kvSecretNameClientSecret: { value: kvSecretNameClientSecret }
      kvSecretNameProvisioningToken: { value: kvSecretNameProvisioningToken }
      directClientId: { value: directClientId }
      directClientSecret: { value: directClientSecret }
      directProvisioningToken: { value: directProvisioningToken }
    }
  }
  identity: {
    type: 'SystemAssigned'
  }
}

// ---------------------------
//
// Reusable parameter schemas and templates for policy definitions
//
// ---------------------------
function policyCommonParams() object {
  return {
    effect: {
      type: 'String'
      metadata: {
        displayName: 'Effect'
      }
      allowedValues: [
        'DeployIfNotExists'
        'Disabled'
      ]
      defaultValue: 'DeployIfNotExists'
    }
    exemptionTagKey: {
      type: 'String'
      defaultValue: exemptionTagKey
    }
    exemptionTagValue: {
      type: 'String'
      defaultValue: exemptionTagValue
    }
    cloud: { type: 'String' }
    memberCid: { type: 'String' }
    sensorUpdatePolicy: { type: 'String' }
    disableProxy: { type: 'Boolean' }
    proxyHost: { type: 'String' }
    proxyPort: { type: 'String' }
    csTags: { type: 'String' }
    pacUrl: { type: 'String' }
    disableProvisioningWait: { type: 'Boolean' }
    disableStart: { type: 'Boolean' }
    provisioningWaitTime: { type: 'String' }
    vdi: { type: 'Boolean' }
    handlerVersion: { type: 'String' }
    autoUpgradeMinorVersion: { type: 'Boolean' }
    enableAutomaticUpgrade: { type: 'Boolean' }
    useKeyVaultRefs: { type: 'Boolean' }
    azureVaultName: { type: 'String' }
    kvSecretNameClientId: { type: 'String' }
    kvSecretNameClientSecret: { type: 'String' }
    kvSecretNameProvisioningToken: { type: 'String' }
    directClientId: { type: 'SecureString' }
    directClientSecret: { type: 'SecureString' }
    directProvisioningToken: { type: 'SecureString' }
  }
}

function policySetParamBindings() object {
  return {
    effect: { value: '[parameters(''effect'')]' }
    exemptionTagKey: { value: '[parameters(''exemptionTagKey'')]' }
    exemptionTagValue: { value: '[parameters(''exemptionTagValue'')]' }
    cloud: { value: '[parameters(''cloud'')]' }
    memberCid: { value: '[parameters(''memberCid'')]' }
    sensorUpdatePolicy: { value: '[parameters(''sensorUpdatePolicy'')]' }
    disableProxy: { value: '[parameters(''disableProxy'')]' }
    proxyHost: { value: '[parameters(''proxyHost'')]' }
    proxyPort: { value: '[parameters(''proxyPort'')]' }
    csTags: { value: '[parameters(''csTags'')]' }
    pacUrl: { value: '[parameters(''pacUrl'')]' }
    disableProvisioningWait: { value: '[parameters(''disableProvisioningWait'')]' }
    disableStart: { value: '[parameters(''disableStart'')]' }
    provisioningWaitTime: { value: '[parameters(''provisioningWaitTime'')]' }
    vdi: { value: '[parameters(''vdi'')]' }
    handlerVersion: { value: '[parameters(''handlerVersion'')]' }
    autoUpgradeMinorVersion: { value: '[parameters(''autoUpgradeMinorVersion'')]' }
    enableAutomaticUpgrade: { value: '[parameters(''enableAutomaticUpgrade'')]' }
    useKeyVaultRefs: { value: '[parameters(''useKeyVaultRefs'')]' }
    azureVaultName: { value: '[parameters(''azureVaultName'')]' }
    kvSecretNameClientId: { value: '[parameters(''kvSecretNameClientId'')]' }
    kvSecretNameClientSecret: { value: '[parameters(''kvSecretNameClientSecret'')]' }
    kvSecretNameProvisioningToken: { value: '[parameters(''kvSecretNameProvisioningToken'')]' }
    directClientId: { value: '[parameters(''directClientId'')]' }
    directClientSecret: { value: '[parameters(''directClientSecret'')]' }
    directProvisioningToken: { value: '[parameters(''directProvisioningToken'')]' }
  }
}

// ---------- Extension deployment templates (VM) ----------
function extensionDeploymentTemplate(isWindows bool) object {
  return {
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
      csTags: { type: 'string' }
      pacUrl: { type: 'string' }
      disableProvisioningWait: { type: 'bool' }
      disableStart: { type: 'bool' }
      provisioningWaitTime: { type: 'string' }
      vdi: { type: 'bool' }
      handlerVersion: { type: 'string' }
      autoUpgradeMinorVersion: { type: 'bool' }
      enableAutomaticUpgrade: { type: 'bool' }
      useKeyVaultRefs: { type: 'bool' }
      azureVaultName: { type: 'string' }
      kvSecretNameClientId: { type: 'string' }
      kvSecretNameClientSecret: { type: 'string' }
      kvSecretNameProvisioningToken: { type: 'string' }
      directClientId: { type: 'securestring' }
      directClientSecret: { type: 'securestring' }
      directProvisioningToken: { type: 'securestring' }
    }
    resources: [
      {
        name: "[concat(parameters('vmName'), '/${extensionResName}')]"
        type: 'Microsoft.Compute/virtualMachines/extensions'
        apiVersion: '2021-07-01'
        location: "[parameters('location')]"
        properties: {
          publisher: '${publisher}'
          type: '${isWindows ? windowsType : linuxType}'
          typeHandlerVersion: "[if(empty(parameters('handlerVersion')), json('null'), parameters('handlerVersion'))]"
          autoUpgradeMinorVersion: "[parameters('autoUpgradeMinorVersion')]"
          enableAutomaticUpgrade: "[parameters('enableAutomaticUpgrade')]"
          settings: {
            cloud: "[parameters('cloud')]"
            member_cid: "[parameters('memberCid')]"
            sensor_update_policy: "[parameters('sensorUpdatePolicy')]"
            disable_proxy: "[parameters('disableProxy')]"
            proxy_host: "[parameters('proxyHost')]"
            proxy_port: "[parameters('proxyPort')]"
            tags: "[parameters('csTags')]"
            // Windows-only fields; harmless on Linux if empty
            pac_url: "[parameters('pacUrl')]"
            disable_provisioning_wait: "[parameters('disableProvisioningWait')]"
            disable_start: "[parameters('disableStart')]"
            provisioning_wait_time: "[parameters('provisioningWaitTime')]"
            vdi: "[parameters('vdi')]"
          }
          protectedSettings: "[if(parameters('useKeyVaultRefs'), json(string(createObject('azure_vault_name', parameters('azureVaultName'), 'kv_secret_name_client_id', parameters('kvSecretNameClientId'), 'kv_secret_name_client_secret', parameters('kvSecretNameClientSecret'), 'kv_secret_name_provisioning_token', parameters('kvSecretNameProvisioningToken')))), json(string(createObject('client_id', parameters('directClientId'), 'client_secret', parameters('directClientSecret'), 'provisioning_token', parameters('directProvisioningToken')))))]"
        }
      }
    ]
  }
}

function extensionDeploymentParameters(isWindows bool) object {
  return {
    vmName: { value: "[field('name')]" }
    location: { value: "[field('location')]" }
    cloud: { value: "[parameters('cloud')]" }
    memberCid: { value: "[parameters('memberCid')]" }
    sensorUpdatePolicy: { value: "[parameters('sensorUpdatePolicy')]" }
    disableProxy: { value: "[parameters('disableProxy')]" }
    proxyHost: { value: "[parameters('proxyHost')]" }
    proxyPort: { value: "[parameters('proxyPort')]" }
    csTags: { value: "[parameters('csTags')]" }
    pacUrl: { value: "[parameters('pacUrl')]" }
    disableProvisioningWait: { value: "[parameters('disableProvisioningWait')]" }
    disableStart: { value: "[parameters('disableStart')]" }
    provisioningWaitTime: { value: "[parameters('provisioningWaitTime')]" }
    vdi: { value: "[parameters('vdi')]" }
    handlerVersion: { value: "[parameters('handlerVersion')]" }
    autoUpgradeMinorVersion: { value: "[parameters('autoUpgradeMinorVersion')]" }
    enableAutomaticUpgrade: { value: "[parameters('enableAutomaticUpgrade')]" }
    useKeyVaultRefs: { value: "[parameters('useKeyVaultRefs')]" }
    azureVaultName: { value: "[parameters('azureVaultName')]" }
    kvSecretNameClientId: { value: "[parameters('kvSecretNameClientId')]" }
    kvSecretNameClientSecret: { value: "[parameters('kvSecretNameClientSecret')]" }
    kvSecretNameProvisioningToken: { value: "[parameters('kvSecretNameProvisioningToken')]" }
    directClientId: { value: "[parameters('directClientId')]" }
    directClientSecret: { value: "[parameters('directClientSecret')]" }
    directProvisioningToken: { value: "[parameters('directProvisioningToken')]" }
  }
}

// ---------- Extension deployment templates (VMSS) ----------
function extensionDeploymentTemplateVmss(isWindows bool) object {
  return {
    '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion: '1.0.0.0'
    parameters: {
      vmssName: { type: 'string' }
      location: { type: 'string' }
      cloud: { type: 'string' }
      memberCid: { type: 'string' }
      sensorUpdatePolicy: { type: 'string' }
      disableProxy: { type: 'bool' }
      proxyHost: { type: 'string' }
      proxyPort: { type: 'string' }
      csTags: { type: 'string' }
      pacUrl: { type: 'string' }
      disableProvisioningWait: { type: 'bool' }
      disableStart: { type: 'bool' }
      provisioningWaitTime: { type: 'string' }
      vdi: { type: 'bool' }
      handlerVersion: { type: 'string' }
      autoUpgradeMinorVersion: { type: 'bool' }
      enableAutomaticUpgrade: { type: 'bool' }
      useKeyVaultRefs: { type: 'bool' }
      azureVaultName: { type: 'string' }
      kvSecretNameClientId: { type: 'string' }
      kvSecretNameClientSecret: { type: 'string' }
      kvSecretNameProvisioningToken: { type: 'string' }
      directClientId: { type: 'securestring' }
      directClientSecret: { type: 'securestring' }
      directProvisioningToken: { type: 'securestring' }
    }
    resources: [
      {
        name: "[concat(parameters('vmssName'), '/${extensionResName}')]"
        type: 'Microsoft.Compute/virtualMachineScaleSets/extensions'
        apiVersion: '2021-07-01'
        location: "[parameters('location')]"
        properties: {
          publisher: '${publisher}'
          type: '${isWindows ? windowsType : linuxType}'
          typeHandlerVersion: "[if(empty(parameters('handlerVersion')), json('null'), parameters('handlerVersion'))]"
          autoUpgradeMinorVersion: "[parameters('autoUpgradeMinorVersion')]"
          enableAutomaticUpgrade: "[parameters('enableAutomaticUpgrade')]"
          settings: {
            cloud: "[parameters('cloud')]"
            member_cid: "[parameters('memberCid')]"
            sensor_update_policy: "[parameters('sensorUpdatePolicy')]"
            disable_proxy: "[parameters('disableProxy')]"
            proxy_host: "[parameters('proxyHost')]"
            proxy_port: "[parameters('proxyPort')]"
            tags: "[parameters('csTags')]"
            pac_url: "[parameters('pacUrl')]"
            disable_provisioning_wait: "[parameters('disableProvisioningWait')]"
            disable_start: "[parameters('disableStart')]"
            provisioning_wait_time: "[parameters('provisioningWaitTime')]"
            vdi: "[parameters('vdi')]"
          }
          protectedSettings: "[if(parameters('useKeyVaultRefs'), json(string(createObject('azure_vault_name', parameters('azureVaultName'), 'kv_secret_name_client_id', parameters('kvSecretNameClientId'), 'kv_secret_name_client_secret', parameters('kvSecretNameClientSecret'), 'kv_secret_name_provisioning_token', parameters('kvSecretNameProvisioningToken')))), json(string(createObject('client_id', parameters('directClientId'), 'client_secret', parameters('directClientSecret'), 'provisioning_token', parameters('directProvisioningToken')))))]"
        }
      }
    ]
  }
}

function extensionDeploymentParametersVmss(isWindows bool) object {
  return {
    vmssName: { value: "[field('name')]" }
    location: { value: "[field('location')]" }
    cloud: { value: "[parameters('cloud')]" }
    memberCid: { value: "[parameters('memberCid')]" }
    sensorUpdatePolicy: { value: "[parameters('sensorUpdatePolicy')]" }
    disableProxy: { value: "[parameters('disableProxy')]" }
    proxyHost: { value: "[parameters('proxyHost')]" }
    proxyPort: { value: "[parameters('proxyPort')]" }
    csTags: { value: "[parameters('csTags')]" }
    pacUrl: { value: "[parameters('pacUrl')]" }
    disableProvisioningWait: { value: "[parameters('disableProvisioningWait')]" }
    disableStart: { value: "[parameters('disableStart')]" }
    provisioningWaitTime: { value: "[parameters('provisioningWaitTime')]" }
    vdi: { value: "[parameters('vdi')]" }
    handlerVersion: { value: "[parameters('handlerVersion')]" }
    autoUpgradeMinorVersion: { value: "[parameters('autoUpgradeMinorVersion')]" }
    enableAutomaticUpgrade: { value: "[parameters('enableAutomaticUpgrade')]" }
    useKeyVaultRefs: { value: "[parameters('useKeyVaultRefs')]" }
    azureVaultName: { value: "[parameters('azureVaultName')]" }
    kvSecretNameClientId: { value: "[parameters('kvSecretNameClientId')]" }
    kvSecretNameClientSecret: { value: "[parameters('kvSecretNameClientSecret')]" }
    kvSecretNameProvisioningToken: { value: "[parameters('kvSecretNameProvisioningToken')]" }
    directClientId: { value: "[parameters('directClientId')]" }
    directClientSecret: { value: "[parameters('directClientSecret')]" }
    directProvisioningToken: { value: "[parameters('directProvisioningToken')]" }
  }
}
