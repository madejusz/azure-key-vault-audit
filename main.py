import logging
import csv
from azure.identity import AzureCliCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys._models import KeyRotationLifetimeAction
from azure.core.exceptions import HttpResponseError, ServiceRequestError
from azure.core.pipeline.transport import RequestsTransport
from requests.exceptions import Timeout

logging.basicConfig(level=logging.WARNING)

credential = AzureCliCredential()
subscription_client = SubscriptionClient(credential)
results = []

print("🔍 Fetching data from all subscriptions...\n")

# Transport with 15s timeout
transport = RequestsTransport(connection_timeout=15, read_timeout=15)

for sub in subscription_client.subscriptions.list():

    # if sub.display_name != "XXXXXXX":
    #     continue

    sub_id = sub.subscription_id
    sub_name = sub.display_name
    print(f"📦 Checking subscription: {sub_name} ({sub_id})")

    kv_mgmt = KeyVaultManagementClient(credential, sub_id)

    try:
        vaults = kv_mgmt.vaults.list()
    except HttpResponseError as e:
        print(f"❌ Failed to list Key Vaults in subscription {sub_id}: {e.status_code} - {e.message}")
        continue
    except Exception as e:
        print(f"❌ Unexpected error listing Key Vaults in subscription {sub_id}: {e}")
        continue

    for kv in vaults:
        kv_name = kv.name
        rg_name = kv.id.split("/")[4]
        kv_uri = f"https://{kv_name}.vault.azure.net/"
        print(f"  ✅ Found Key Vault: {kv_name} in resource group {rg_name}")

        connection_status = "✅ success"

        try:
            key_client = KeyClient(vault_url=kv_uri, credential=credential, transport=transport)
        except Exception as e:
            connection_status = f"❌ KeyClient error: {type(e).__name__}"
            print(f"    ❌ Could not initialize KeyClient: {connection_status}")
            continue

        try:
            for key_prop in key_client.list_properties_of_keys():
                key_name = key_prop.name
                older_versions_count = 0
                rotation_enabled = False
                has_rotate_action = False
                rotate_after = "-"

                try:
                    key = key_client.get_key(key_name)
                    expires = key.properties.expires_on
                except HttpResponseError as e:
                    print(f"    ❌ HTTP Error retrieving key '{key_name}': {e.status_code} - {e.message}")
                    if hasattr(e, 'error') and e.error and hasattr(e.error, 'code'):
                        print(f"       Azure error code: {e.error.code}")
                    continue
                except Exception as e:
                    print(f"    ⚠️ General error retrieving key '{key_name}': {e}")
                    continue

                try:
                    versions = list(key_client.list_properties_of_key_versions(key_name))
                    older_versions_count = max(0, len(versions) - 1)
                except Exception as e:
                    print(f"    ⚠️ Could not retrieve versions for key '{key_name}': {e}")
                    older_versions_count = "-"

                try:
                    rotation_policy = key_client.get_key_rotation_policy(key_name)
                    rotation_enabled = bool(rotation_policy.lifetime_actions)

                    for action in rotation_policy.lifetime_actions:
                        if isinstance(action, KeyRotationLifetimeAction):
                            action_type = str(action.action).lower()
                            if action_type == "rotate":
                                has_rotate_action = True
                                rotate_after = getattr(action, "time_after_create", "-")

                except HttpResponseError as e:
                    print(f"    ⚠️ No rotation policy for '{key_name}': {e.status_code} - {e.message}")
                    rotation_enabled = False
                except Exception as e:
                    print(f"    ⚠️ General error getting rotation policy for '{key_name}': {e}")
                    rotation_enabled = False

                results.append({
                    "subscription_name": sub_name,
                    "subscription_id": sub_id,
                    "resource_group": rg_name,
                    "key_vault": kv_name,
                    "key_name": key_name,
                    "expires_on": expires.isoformat() if expires else "None",
                    "rotation_policy_enabled": rotation_enabled,
                    "has_rotate_action": has_rotate_action,
                    "rotate_after": rotate_after,
                    "older_key_versions_count": older_versions_count,
                    "connection_status": connection_status
                })

        except (HttpResponseError, Timeout, ServiceRequestError) as e:
            connection_status = f"❌ KV access error: {type(e).__name__}"
            print(f"    ❌ Cannot list keys in {kv_name}: {connection_status}")
        except Exception as e:
            connection_status = f"❌ General connection error: {type(e).__name__}"
            print(f"    ⚠️ Unexpected error listing keys in {kv_name}: {e}")

        if not any(r["key_vault"] == kv_name for r in results):
            results.append({
                "subscription_name": sub_name,
                "subscription_id": sub_id,
                "resource_group": rg_name,
                "key_vault": kv_name,
                "key_name": "-",
                "expires_on": "-",
                "rotation_policy_enabled": "-",
                "has_rotate_action": "-",
                "rotate_after": "-",
                "older_key_versions_count": "-",
                "connection_status": connection_status
            })

print("\n📋 Summary of Keys:")

for r in results:
    print(f"{r['subscription_name']} | {r['resource_group']} | {r['key_vault']} | "
          f"{r['key_name']} | Expires: {r['expires_on']} | "
          f"Auto-Rotation: {r['rotation_policy_enabled']} | "
          f"Rotate Action: {r['has_rotate_action']} | Rotate After: {r['rotate_after']} | "
          f"Old Versions: {r['older_key_versions_count']} | "
          f"Status: {r['connection_status']}")

# 📁 Zapis do pliku CSV
output_file = "keyvault_report.csv"
try:
    with open(output_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"\n✅ Report saved to: {output_file}")
except Exception as e:
    print(f"\n❌ Failed to save report: {e}")