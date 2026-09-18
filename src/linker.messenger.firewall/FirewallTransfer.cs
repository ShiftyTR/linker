using linker.messenger.decenter;
using linker.messenger.signin;
using linker.nat;

namespace linker.messenger.firewall
{
    public sealed class FirewallTransfer
    {
        public int Count => firewallClientStore.GetAll().Count(c => c.GroupId == signInClientStore.Group.Id);

        private readonly IFirewallClientStore firewallClientStore;
        private readonly ISignInClientStore signInClientStore;
        private readonly LinkerFirewall linkerFirewall;
        private readonly CounterDecenter counterDecenter;
        private readonly object policyGate = new();
        private bool managedPolicy;
        public bool AllowRemoteManagement => !Volatile.Read(ref managedPolicy);

        public FirewallTransfer(IFirewallClientStore firewallClientStore, SignInClientState signInClientState,
            ISignInClientStore signInClientStore, LinkerFirewall linkerFirewall, CounterDecenter counterDecenter)
        {
            this.firewallClientStore = firewallClientStore;
            this.signInClientStore = signInClientStore;
            this.linkerFirewall = linkerFirewall;
            this.counterDecenter = counterDecenter;
            signInClientState.OnSignInSuccess += Reset;
        }
        private async Task Reset(int times)
        {
            await Task.Run(() =>
            {
                BuildRules();
            }).ConfigureAwait(false);
        }
        private void BuildRules()
        {
            lock (policyGate)
            {
                linkerFirewall.ApplyRules(firewallClientStore.GetEnabled(signInClientStore.Group.Id).Select(c => (LinkerFirewallRuleInfo)c).ToList(), firewallClientStore.State);
                counterDecenter.SetValue("firewall", Count);
            }
        }

        // Localtonet supplies a complete policy. Publish it once, after every stored rule
        // and the enable state have been updated, rather than briefly disabling enforcement.
        public void Replace(List<FirewallRuleInfo> infos, LinkerFirewallState state)
        {
            // Managed clients accept changes only through their authenticated application
            // control channel, never through another Linker peer's legacy management API.
            Volatile.Write(ref managedPolicy, true);
            LinkerFirewall.ValidateRules(infos.Where(r => !r.Disabled));
            lock (policyGate)
            {
                var group = signInClientStore.Group.Id;
                var previous = firewallClientStore.GetAll().Where(r => r.GroupId == group).ToList();
                var previousState = firewallClientStore.State;
                foreach (var rule in infos) rule.GroupId = group;
                try
                {
                    firewallClientStore.Remove(previous.Select(r => r.Id).ToList());
                    if (!firewallClientStore.Add(infos)) throw new InvalidOperationException("Firewall policy could not be stored.");
                    firewallClientStore.SetState(state);
                    BuildRules();
                }
                catch
                {
                    firewallClientStore.Remove(infos.Select(r => r.Id).ToList());
                    firewallClientStore.Add(previous);
                    firewallClientStore.SetState(previousState);
                    throw;
                }
            }
        }

        public bool State(LinkerFirewallState state)
        {
            lock (policyGate) { firewallClientStore.SetState(state); BuildRules(); }
            return true;
        }
        public bool Check(FirewallCheckInfo info)
        {
            return firewallClientStore.Check(info);
        }

        public List<FirewallRuleInfo> Get()
        {
            lock (policyGate) return firewallClientStore.GetAll().ToList();
        }
        public FirewallListInfo Get(FirewallSearchInfo info)
        {
            return new FirewallListInfo
            {
                List = firewallClientStore.GetAll(info).ToList(),
                State = firewallClientStore.State
            };
        }
        public bool Add(FirewallRuleInfo info)
        {
            LinkerFirewall.ValidateRules(info.Disabled ? [] : new[] { info });
            lock (policyGate) { info.GroupId = signInClientStore.Group.Id; firewallClientStore.Add(info); BuildRules(); }
            return true;
        }
        public bool Add(List<FirewallRuleInfo> infos)
        {
            LinkerFirewall.ValidateRules(infos.Where(r => !r.Disabled));
            lock (policyGate)
            {
                foreach (var item in infos) item.GroupId = signInClientStore.Group.Id;
                firewallClientStore.Add(infos);
                BuildRules();
            }
            return true;
        }
        public bool Remove(string id)
        {
            lock (policyGate) { firewallClientStore.Remove(id); BuildRules(); }
            return true;
        }
        public bool Remove(List<string> ids)
        {
            lock (policyGate) { firewallClientStore.Remove(ids); BuildRules(); }
            return true;
        }

    }
}
