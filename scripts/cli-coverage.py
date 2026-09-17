#!/usr/bin/env python3
"""Deterministic, exhaustive command disposition; pending work blocks release."""
import hashlib,json,pathlib,sys
root=pathlib.Path(__file__).resolve().parents[1]
files={'control-plane':root/'contracts/platform-draft/control-plane.json','storage':root/'contracts/openapi/storage.json','s3':root/'contracts/openapi/s3.json'}
compute_commands = {
 'listComputeProjects':'pipe compute projects', 'listComputeImages':'pipe compute images',
 'listComputeFlavors':'pipe compute flavors', 'getComputePricing':'pipe compute pricing',
 'listComputeVms':'pipe compute vms list', 'getComputeVm':'pipe compute vms get',
 'createComputeVm':'pipe compute vms create', 'startComputeVm':'pipe compute vms start',
 'stopComputeVm':'pipe compute vms stop', 'rebootComputeVm':'pipe compute vms reboot',
 'deleteComputeVm':'pipe compute vms delete', 'updateComputeBilling':'pipe compute vms billing',
 'getComputeOperation':'pipe compute operations', 'getComputeUsage':'pipe compute usage',
}
kv_commands = {
 'getKvPricing':'pipe kv pricing', 'listKvInstances':'pipe kv instances list',
 'createKvInstance':'pipe kv instances create', 'deleteKvInstance':'pipe kv instances delete',
 'listKvCredentials':'pipe kv credentials list', 'createKvCredential':'pipe kv credentials create',
 'revokeKvCredential':'pipe kv credentials revoke',
}
durable_commands = {
 'getDurablePricing':'pipe durable pricing', 'listDurableNamespaces':'pipe durable namespaces list',
 'createDurableNamespace':'pipe durable namespaces create', 'revokeDurableNamespace':'pipe durable namespaces delete',
 'updateDurableLimit':'pipe durable namespaces limit', 'createDurableCredential':'pipe durable credentials create',
 'revokeDurableCredential':'pipe durable credentials revoke', 'listDurableObjects':'pipe durable objects',
 'getDurableActivity':'pipe durable activity', 'executeCustomerDurableAction':'pipe durable state / sql / migrate / blobs / delete-object',
 'executeDurableAction':'pipe durable state / sql / migrate / blobs / delete-object --credential',
 'getCustomerDurableOperation':'pipe durable operation', 'getDurableOperation':'pipe durable operation --credential',
}
hosting_commands = {
 'getHostingPricing':'pipe hosting pricing', 'getHostingAccount':'pipe hosting account',
 'registerHostingAccount':'pipe hosting account register', 'purchaseHostingPlan':'pipe hosting plans purchase',
 'createHostingCredential':'pipe hosting credentials create', 'revokeHostingCredential':'pipe hosting credentials revoke',
 'listHostingSites':'pipe hosting sites list', 'createHostingSite':'pipe hosting sites create',
 'getHostingBilling':'pipe hosting billing', 'getHostingSite':'pipe hosting sites get',
 'deleteHostingSite':'pipe hosting sites delete', 'listHostingReleases':'pipe hosting releases list',
 'uploadHostingRelease':'pipe hosting releases upload / deploy', 'getHostingLogs':'pipe hosting sites logs',
 'migrateHostingSite':'pipe hosting sites migrate / deploy', 'activateHostingRelease':'pipe hosting sites activate / deploy',
 'deactivateHostingSite':'pipe hosting sites deactivate', 'allocateHostingStorage':'pipe hosting sites storage',
 'deleteHostingRelease':'pipe hosting releases delete', 'listHostingDomains':'pipe hosting domains list',
 'createHostingDomain':'pipe hosting domains create', 'deleteHostingDomain':'pipe hosting domains delete',
 'verifyHostingDomain':'pipe hosting domains verify',
}
billing_workflows = {
 'infrastructure.stripe.config':'pipe billing card config',
 'infrastructure.stripe.history':'pipe billing card list',
 'infrastructure.stripe.checkout':'pipe billing card checkout',
 'infrastructure.stripe.reconcile':'pipe billing card reconcile',
 'platform.billing.checkout':'pipe billing checkout',
 'platform.billing.plan_checkout':'pipe billing plan-checkout',
 'platform.billing.portal':'pipe billing portal',
 'platform.billing.settings':'pipe billing settings',
 'platform.solana.create':'pipe billing solana create',
 'platform.solana.verify':'pipe billing solana verify',
 'platform.solana.sync':'pipe billing solana sync',
}
customer_commands = {
 'platform.api_keys':'pipe account keys list', 'platform.create_api_key':'pipe account keys create',
 'platform.update_api_key':'pipe account keys update', 'platform.revoke_api_key':'pipe account keys revoke',
 'platformCliAccount':'pipe account get', 'platform.identities':'pipe account identities',
 'platform.wallet_links':'pipe account wallets', 'platform.profile':'pipe account update',
 'platform.referral_summary':'pipe account referrals', 'platform.rotate_referral_code':'pipe account rotate-referral',
 'platform.organizations':'pipe org list', 'platform.create_organization':'pipe org create',
 'platform.memberships':'pipe org members list', 'platform.update_membership':'pipe org members update',
 'platform.remove_membership':'pipe org members delete', 'platform.invites':'pipe org invites list',
 'platform.create_invite':'pipe org invites create', 'platform.revoke_invite':'pipe org invites revoke',
 'platform.accept_invite':'pipe org accept',
 'platform.billing.account':'pipe billing balance', 'platform.billing.account_ledger':'pipe billing ledger',
 'platform.billing.account_usage':'pipe billing usage', 'platform.billing.org_account':'pipe billing balance --org',
 'platform.billing.org_ledger':'pipe billing ledger --org', 'platform.billing.org_usage':'pipe billing usage --org',
 'platform.billing.summary':'pipe billing get', 'platform.billing.invoices':'pipe billing invoices',
 'platform.billing.subscriptions':'pipe billing subscriptions',
}
hosting_replay={'registerHostingAccount','purchaseHostingPlan','createHostingCredential','revokeHostingCredential','uploadHostingRelease','migrateHostingSite','deleteHostingSite'}
public_diagnostics = {
 'control.health', 'control.readiness', 'control.signingKeys', 'control.nodeEligibility',
 'storage.health', 'storage.wallet_get', 'storage.x402_discover',
 'storage.epoch_leaves', 'storage.whoami', 'storage.mesh', 'storage.stats',
}
def native_exclusion(oid):
 if oid.startswith('storage.durable.'):
  return 'Retained native Durable Objects requires operator authority in payment mode. Customer commands use the paid control-plane Durable Objects workflow and must not bypass its authorization or billing.'
 if oid in {'storage.auth','storage.wallet_new.v1.wallet','storage.wallet_new.v1.wallet.new'}:
  return 'Legacy wallet-secret issuance requires operator authority in payment mode, or demo-only admission. Platform CLI authentication never submits wallet secrets or accepts operator tokens.'
 if oid in {'storage.demo','storage.hotkey'}:
  return 'Demo wallet discovery and synthetic coalescing workload are test/development interfaces, excluded from the production customer client.'
 if oid in {'storage.get_cache','storage.head_cache','storage.put_cache','storage.del_cache','storage.mutationStatus'}:
  return 'Retained native cache protocol uses native bearer keys or legacy cumulative payment vouchers, which are separate from customer CLI/S3 credentials. Supported customer object/condition/range/recovery workflows use pipe storage with SigV4; native shared-key/voucher admission is outside this rebuild.'
 if oid in {'storage.open_session','storage.renew_session'}:
  return 'Specialized prepaid native table-read sessions require native/voucher admission and per-node signed tickets. This legacy protocol is outside the customer object client; CLI tokens are not reinterpreted as native tokens.'
 if oid.startswith(('storage.deposit_plan.', 'storage.withdraw_')):
  return 'Unsigned plans for the retained native token deposit/withdrawal program are outside platform USDC/card billing. They do not move funds and are never exposed as generic financial calls; existing legacy wallet credit remains readable through storage.wallet_get.'
 raise ValueError('Unreviewed native operation '+oid)
rows=[]
for service,file in files.items():
 spec=json.loads(file.read_text())
 items = spec['paths'].items() if service != 's3' else [(op.get('path',''), {op.get('method','GET').lower():op}) for op in spec['x-pipe-s3-operations']]
 for path,item in items:
  for method,op in item.items():
   if not isinstance(op,dict) or 'operationId' not in op:continue
   oid=op['operationId'];status='pending';disposition='exclusion';command=None;reason='Requires a reviewed platform workflow or credential adapter before release.'
   if service=='s3':
    status='implemented';disposition='workflow-internal';command='pipe storage';reason='Preserved custom SigV4, XML and durable multipart implementation.'
   elif oid in public_diagnostics:
    status='implemented';disposition='advanced';command='pipe api call '+oid;reason='Reviewed anonymous diagnostics with fixed profile endpoints, bounded JSON, original contract validation and no credential forwarding. Native ingress availability is deployment-dependent; a 404 remains a resource/route error.'
   elif service=='storage':
    status='excluded';reason=native_exclusion(oid)
   elif oid in {'platform.phone.start_handler','platform.phone.check_handler'}:
    status='excluded';reason='Website-only phone/Turnstile verification and signup-credit anti-abuse flow. Existing website session, challenge and origin requirements are preserved; CLI session credentials are not accepted.'
   elif oid == 'getStoragePricing':
    status='implemented';disposition='dedicated';command='pipe pricing';reason='Pinned public customer storage pricing through the reviewed REST validation layer.'
   elif oid in compute_commands:
    status='implemented';disposition='dedicated';command=compute_commands[oid];reason='Typed requests, contract validation, account-bound durable idempotency, bounded pagination and operation waiting.'
   elif oid in kv_commands:
    status='implemented';disposition='dedicated';command=kv_commands[oid];reason='Owned resource intents and client-generated material persisted securely before activation; exact management recovery, bounded TLS/RESP2 data workflows without mutation replay.'
   elif oid in durable_commands:
    status='implemented';disposition='dedicated';command=durable_commands[oid];reason='Paid customer execution with encrypted original payload and idempotency recovery, exact credential activation, scope-bound product access, bounded operation polling and application results.'
   elif oid in hosting_commands:
    status='implemented';disposition='dedicated';command=hosting_commands[oid];reason='Typed customer management, paid purchase recovery, encrypted immutable deployment snapshots and bounded waits; uncertain settings use observation without replay. Private host/Spin/DNS workflow and exact accounting fixtures.'
   elif oid in {'platform.api_keys','platform.create_api_key','platform.update_api_key','platform.revoke_api_key'}:
    status='implemented';disposition='dedicated';command=customer_commands[oid];reason='Explicit canonical account ownership and credential-type/scopes; session-only writes, separate billing grant for creation/settings, material encrypted before activation, no mutation replay, preserved counters and revocation.'
   elif oid in billing_workflows:
    status='implemented';disposition='dedicated';command=billing_workflows[oid];reason='Exact integer amounts and encrypted original payment/checkout IDs; hosted provider idempotency and owned durable records, sandbox reconciliation, current billing role and session-only financial mutations.'
   elif oid in customer_commands:
    status='implemented';disposition='dedicated';command=customer_commands[oid];reason='Canonical customer scopes, current organization roles, separate billing units, bounded history pages and encrypted mutation observations; no automatic mutation replay or implicit invitation-secret output.'
   elif oid.startswith('platformCli'):
    status='implemented';disposition='workflow-internal';command='pipe auth';reason='Generalized CLI authentication and context.'
   elif path.startswith('/v1/customer/cli/'):
    status='implemented';disposition='workflow-internal';command='pipe auth / storage / usage';reason='Preserved wallet CLI compatibility operations.'
   elif path.startswith('/v1/payments/'):
    status='implemented';disposition='workflow-internal';command='pipe payments';reason='Managed exact-payment and recovery workflow; arbitrary API invocation is prohibited.'
   elif path.startswith('/v1/compute/') or path.startswith('/v1/customer/kv/') or path.startswith('/v1/customer/durable/') or path.startswith('/v1/customer/hosting/') or path in ['/v1/kv/pricing','/v1/durable/pricing','/v1/hosting/pricing','/v1/pricing']:
    if method=='get':status='implemented';disposition='advanced';command='pipe api call '+oid;reason='Explicit customer read using generalized CLI principal or public pricing.'
   elif 'platform.legacy.' in oid or oid in ['platform.record_analytics','platform.google_complete','platform.connect_google','platform.session','platform.logout','platform.list_sessions','platform.revoke_session','platform.link_wallet']:
    status='excluded';reason='Browser-only authorization/analytics or deliberately disabled historical identity operation.'
   rows.append({'service':service,'operation_id':oid,'method':method.upper(),'path':path,'disposition':disposition,'implementation_status':status,'command':command,'reason':reason,'credentials':op.get('security',[]),'feature_conditions':op.get('x-pipe-availability',{}),'retry_policy':'read-only' if method in ['get','head'] else 'managed-billing-journal-recovery' if oid in billing_workflows else 'observe-current-state-never-replay' if oid in customer_commands or oid in hosting_commands and oid not in hosting_replay else 'read-current-setting-never-replay' if oid=='updateDurableLimit' else 'resume-exact-idempotency-only' if oid in compute_commands or oid in kv_commands or oid in durable_commands or oid in hosting_replay else 'managed-workflow-only','verification_fixture':('pipenetwork::billing::tests::platform_cli_billing_hosted_replay_and_sandbox_settlement; CLI billing_workflows tests' if oid in billing_workflows else 'advanced::tests; lattice-router tests::cli_diagnostics::executable_public_diagnostics_preserve_legacy_credit_and_never_forward_credentials; control public contracts' if oid in public_diagnostics else 'compute::tests::platform_cli_executable_wallet_and_vm_lifecycle; CLI compute_tests; pipe-transports openssh fixture' if oid in compute_commands else 'kv::tests::platform_cli_executable_kv_management_recovery; scripts/test-kv-workflow.py; pipe-transports tests/kv.rs' if oid in kv_commands else 'durable::tests::platform_cli_real_storage_workflow; CLI durable_tests; scripts/test-customer-durable.py' if oid in durable_commands else 'hosting::integration_tests::platform_cli_real_host_workflow; scripts/test-cli-hosting.py; CLI hosting_tests' if oid in hosting_commands else 'pipenetwork::cli_tests::platform_cli_canonical_accounts_organizations_and_billing; CLI customer_tests' if oid in customer_commands else 'cli_auth::tests; tests/cli_contract.rs' if oid.startswith('platformCli') else 'baseline cargo test' if status=='implemented' else None), 'advanced_access':(oid == 'getStoragePricing' or oid in public_diagnostics or oid in compute_commands or oid in kv_commands or oid in hosting_commands or oid in customer_commands and oid!='platform.referral_summary' or (oid in durable_commands and oid!='getDurableOperation')) and method=='get', 'required_cli_scopes':op.get('x-pipe-cli-scopes',[]), 'conditional_cli_scopes':op.get('x-pipe-cli-conditional-scopes',{}), 'allowed_cli_credential_kinds':op.get('x-pipe-cli-credential-kinds',[])})
value={'version':1,'release_ready':all(r['implementation_status']!='pending' for r in rows),'specifications':{k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in files.items()},'operations':sorted(rows,key=lambda r:(r['service'],r['operation_id']))}
data=json.dumps(value,indent=2,sort_keys=True)+'\n';out=root/'contracts/coverage.json'
if '--check' in sys.argv:
 assert out.read_text()==data,'coverage manifest drift; regenerate and review'
else:out.write_text(data)
print(f"{len(rows)} operations; {sum(r['implementation_status']=='pending' for r in rows)} pending; release_ready={value['release_ready']}")

if "--release" in sys.argv and not value["release_ready"]:
 raise SystemExit("Release blocked: public operations still have pending client dispositions.")
