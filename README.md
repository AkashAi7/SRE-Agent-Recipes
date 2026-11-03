# Azure SRE Agent recipes

Three ready-to-run scripts for a first hands-on with **Azure SRE Agent**. Each one deploys a sample app, an Azure Monitor alert on it, and an SRE agent with an incident response plan. Then you break the app and watch the agent investigate.

| Script | Deploys | Alert | Break does |
|---|---|---|---|
| [sre-vm.ps1](sre-vm.ps1) | Ubuntu VM running an nginx web app | CPU above 80% | stops nginx and maxes out the CPU |
| [sre-appservice.ps1](sre-appservice.ps1) | Linux App Service (B1) running a Node.js app | more than 5 HTTP 5xx errors in 5 min | makes every request return HTTP 500 |
| [sre-aks.ps1](sre-aks.ps1) | AKS cluster (2 nodes) running a web app | pods not ready | sets a bad image and adds a crash-looping pod |

Each script also creates the **SRE agent** (in Review mode, so it asks before it changes anything), an **incident response plan** that hands the alert to the agent, and a **sanity runbook** in the agent's memory.

## Run it in Azure Cloud Shell

1. Open <https://shell.azure.com> and choose **PowerShell**. (In Bash, start the scripts with `pwsh`, for example `pwsh ./sre-vm.ps1`.)
2. Run:

   ```powershell
   git clone https://github.com/AkashAi7/SRE-Agent-Recipes
   cd SRE-Agent-Recipes
   ./sre-vm.ps1          # or ./sre-appservice.ps1 or ./sre-aks.ps1
   ```

3. Press **Enter** to use your current subscription, or type part of another subscription's name.

You then get this menu:

```text
 Azure SRE Agent hackathon kit - Linux VM
 Subscription : My subscription (xxxxxxxx-...)
 Workload     : rg-vmjane3f-workload  [not deployed]
 SRE agent    : sre-vmjane3f-1a2b  [not deployed]
 Next step    : 1) Deploy everything
  1) Deploy everything: Ubuntu VM + nginx app + CPU alert + SRE agent + incident plan (~15 min)
  2) Break the app (start an incident) and watch the agent respond
  3) Fix the app
  4) Status: app health, alerts, agent, incidents
  5) Watch the agent pick up and investigate the incident
  6) Prompts to try in the agent chat
  7) Pre-flight checks only (region, capacity, quota, permissions)
  8) Switch subscription
  0) Exit
```

## The flow: 1, 2, 3

1. **Deploy everything.** Press **Enter** to accept the default region (`westus2`). The script first checks the region, size, quota and your permissions, and offers alternatives if something isn't available (press **Enter** to take the first one). Deploy takes about 10 min (App Service), 15 min (VM) or 20 min (AKS).
2. **Break the app**, then press **Enter** to watch. The alert fires after about 5-10 min, the agent opens an incident about a minute later, and you see its steps live. When it pauses for you, open <https://sre.azure.com>, pick your agent, open **Incidents** and answer it:
   - **Approve** a command it wants to run (for example its fix), or
   - **Authorize** it to use your access for one call (its own identity is read-only).

   Option **6** has prompts to try in the chat.
3. **Fix the app**, or approve the agent's fix. The alert resolves by itself after about 5-10 min.

Cloud Shell closes after about 20 min without input. If that happens, run the script again: it reuses everything that is already deployed.

## What you need

- **Owner** (or Contributor + User Access Administrator) on the subscription.
- Nothing else in Cloud Shell. On your own machine: Azure CLI (`az login`), PowerShell 7, and for AKS `kubectl` (`az aks install-cli`).
- Names are built from your user name, so several participants can share one subscription.

## Clean up (manual)

Each script creates two resource groups: `rg-<prefix>-workload` and `rg-<prefix>-agent` (the menu shows your prefix, for example `rg-vmjane3f-workload`). When you are done, delete both:

```powershell
az group delete -n rg-<prefix>-workload --yes --no-wait
az group delete -n rg-<prefix>-agent --yes --no-wait
```

- The agent bills 4 AAU per hour until it is deleted ([pricing](https://learn.microsoft.com/azure/sre-agent/pricing-billing)).
- In the current preview, deleting the agent can fail ([microsoft/sre-agent#362](https://github.com/microsoft/sre-agent/issues/362)). If `rg-<prefix>-agent` doesn't go away, try again later.
- Optional: the agent's subscription-level **Monitoring Contributor** role assignment stays behind. Remove it in the subscription's **Access control (IAM)**, where it shows as "Identity not found".

## If something goes wrong

- **Region or size not available:** pick one of the alternatives that pre-flight offers.
- **No incident yet:** the alert takes 5-10 min to fire. Use **5** (Watch) or **4** (Status).
- **"Agent API not reachable yet":** your access to the agent takes a few minutes to apply. Choose **1** again; it only finishes the missing steps.
- **The investigation stops at "PendingUserInput":** that's expected. The agent is waiting for you in sre.azure.com > your agent > **Incidents**.

## Options

Every step can also run without the menu, for example `./sre-vm.ps1 -Action Deploy -Location westus2`.

| Parameter | Default | What it does |
|---|---|---|
| `-Action` | `Menu` | `Deploy`, `Break`, `Watch`, `Fix`, `Status` or `Preflight` |
| `-SubscriptionId` | current subscription | Subscription to use |
| `-Location` | `westus2` | Region (no region prompt when given) |
| `-Prefix` | built from your user name | Name prefix: 2-10 lowercase letters or digits, starting with a letter |
| `-AccessLevel` | `Low` | `High` lets the agent run approved fixes with its own identity |
| `-VmSize` / `-Sku` / `-NodeSize` | `Standard_B2s_v2` / `B1` / `Standard_D2s_v5` | VM size / App Service plan / AKS node size |

The SRE Agent APIs these scripts use are in preview and may change. Tested end to end in `westus2`.
