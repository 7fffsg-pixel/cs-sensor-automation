@description('Name of the Azure Key Vault containing Falcon API credentials and provisioning token.')
param azureVaultName string

resource policyDefinition 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: 'deploy-falcon-from-keyvault'
  properties: {
    displayName: 'Deploy CrowdStrike Falcon Sensor from Key Vault'
    policyType: 'Custom'
    mode: 'Indexed'
    description: 'Ensures all VMs have the CrowdStrike Falcon Sensor installed using secrets stored in Azure Key Vault.'
    metadata: {
      category: 'Security'
      version: '1.0.0'
    }
    parameters: {
      azureVaultName: {
        type: 'String'
        metadata: {
          description: 'Name of the Azure Key Vault containing Falcon API credentials and provisioning token.'
        }
      }
    }
    policyRule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.Compute/virtualMachines'
          }
        ]
      }
      then: {
        effect: 'DeployIfNotExists'
        details: {
          type: 'Microsoft.Compute/virtualMachines/extensions'
          roleDefinitionIds: [
            // VM Contributor
            '/providers/microsoft.authorization/roleDefinitions/fd9d4e06-7aa7-4a1a-8f29-6a7463f1a388'
          ]
          existenceCondition: {
            field: 'Microsoft.Compute/virtualMachines/extensions/type'
            equals: 'CrowdStrikeFalconSensor'
          }
          deploymentScope: 'resourceGroup'
          deploymentMode: 'incremental'
          resourceGroupName: '[resourceGroup().name]'
          resourceName: "[format('{0}/CrowdStrikeFalconSensor', field('name'))]"
          location: "[field('location')]"
          properties: {
            publisher: 'CrowdStrike'
            type: 'CrowdStrikeFalconSensor'
            typeHandlerVersion: '1.0'
            autoUpgradeMinorVersion: true
            protectedSettings: {
              azure_vault_name: "[parameters('azureVaultName')]"
            }
          }
        }
      }
    }
  }
}
