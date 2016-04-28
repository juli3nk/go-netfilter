package iptables

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
)

var (
	BuiltInChains = map[string][]string{
		"filter": {"INPUT", "FORWARD", "OUTPUT"},
		"nat": {"PREROUTING", "OUTPUT", "POSTROUTING"},
		"mangle": {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"},
		"raw": {"PREROUTING", "OUTPUT"},
		"security": {"INPUT", "FORWARD", "OUTPUT"},
	}
)

type IPTables struct {
	Binary	string
	Wait	bool
}

func New(ipversion int, wait bool) (*IPTables, error) {
	if ipversion != 4 && ipversion != 6 {
		return nil, fmt.Errorf("IP version must be 4 or 6")
	}

	binary := "iptables"
	if ipversion == 6 {
		binary = "ip6tables"
	}

	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, err
	}

	return &IPTables{
		Binary: path,
		Wait: wait,
	}, nil
}

// ListOptions is the optional values for List method.
type ListOptions struct {
	Chain		string
	Verbose		bool
	Numeric		bool
	Exact		bool
	LineNumbers	bool
}

type ListOutputChain struct {
	Name		string
	BuiltIn		bool
	Policy		string
	Packets		string
	Bytes		string
	Reference	int
}

type ListOutputRule struct {
	Num		int
	Pkts		int
	Bytes		string
	Target		string
	Prot		string
	Opt		string
	In		string
	Out		string
	Source		string
	Destination	string
	Other		string
}

var ListOutput map[ListOutputChain][]ListOutputRule

// List all rules in the selected chain. If no chain is selected, all chains are listed.
func (iptables *IPTables) List(table string, opts *ListOptions) (map[ListOutputChain][]ListOutputRule, error) {
	params := []string{"-t", table}

	if opts.Verbose {
		params = append(params, "-v")
	}

	if opts.Numeric {
		params = append(params, "-n")
	}

	if opts.Exact {
		params = append(params, "-x")
	}

	if opts.LineNumbers {
		params = append(params, "--line-numbers")
	}

	params = append(params, "-L")

	if opts.Chain != "" {
		params = append(params, opts.Chain)
	}

	return iptables.runList(table, opts, params...)
}

// Insert one or more rules in the selected chain at the head of the chain.
func (iptables *IPTables) Insert(table, chain string, rulespec ...string) error {
	params := append([]string{"-t", table, "-I", chain}, rulespec...)

	return iptables.run(params...)
}

// Insert one or more rules in the selected chain as the given rule number.
// So, if the rule number is 1, the rule or rules are inserted at the head of the chain.
func (iptables *IPTables) InsertNum(table, chain string, rulenum int, rulespec ...string) error {
	params := append([]string{"-t", table, "-I", chain, strconv.Itoa(rulenum)}, rulespec...)

	return iptables.run(params...)
}

// Append one or more rules to the end of the selected chain.
// When the source and/or destination names resolve to more than one address,
// a rule will be added for each possible address combination.
func (iptables *IPTables) Append(table, chain string, rulespec ...string) error {
	params := append([]string{"-t", table, "-A", chain}, rulespec...)

	return iptables.run(params...)
}

// Replace a rule in the selected chain.
// If the source and/or destination names resolve to multiple addresses,
// the command will fail. Rules are numbered starting at 1.
func (iptables *IPTables) Replace(table, chain string, rulenum int, rulespec ...string) error {
	params := append([]string{"-t", table, "-R", chain, strconv.Itoa(rulenum)}, rulespec...)

	return iptables.run(params...)
}

// Delete one or more rules from the selected chain.
func (iptables *IPTables) Delete(table, chain string, rulespec ...string) error {
	params := append([]string{"-t", table, "-D", chain}, rulespec...)

	return iptables.run(params...)
}

// Delete one rule specified as a number in the chain (starting at 1 for the first rule).
func (iptables *IPTables) DeleteNum(table, chain string, rulenum int) error {
	params := []string{"-t", table, "-D", chain, strconv.Itoa(rulenum)}

	return iptables.run(params...)
}

// Set the policy for the chain to the given target.
// See the section TARGETS for the legal targets.
// Only built-in (non-user-defined) chains can have policies,
// and neither built-in nor user-defined chains can be policy targets.
func (iptables *IPTables) Policy(table, chain, target string) error {
	if ! IsBuiltInChain(table, chain) {
		return fmt.Errorf("Policy only applied to Built-in chain")
	}

	if target != "ACCEPT" || target != "DROP" {
		return fmt.Errorf("Policy only accept the 2 targets ACCEPT and DROP")
	}

	params := []string{"-t", table, "-P", chain, target}

	return iptables.run(params...)
}

// Flush all the chains.
// This is equivalent to deleting all the rules one by one.
func (iptables *IPTables) Flush(table string) error {
	params := []string{"-t", table, "-F"}

	return iptables.run(params...)
}

// Flush the selected chain.
// This is equivalent to deleting all the rules one by one.
func (iptables *IPTables) FlushChain(table, chain string) error {
	params := []string{"-t", table, "-F", chain}

	return iptables.run(params...)
}

// ZeroOptions is the optional values Chain and RuleNum use by Zero method.
type ZeroOptions struct {
	Chain	string
	RuleNum	int
}

// Zero the packet and byte counters in all chains, or only the given chain, or only the given rule in a chain.
func (iptables *IPTables) Zero(table string, opts *ZeroOptions) error {
	params := []string{"-Z"}

	if opts.Chain != "" {
		params = append(params, opts.Chain)
	}

	if opts.RuleNum > 0 {
		params = append(params, strconv.Itoa(opts.RuleNum))
	}

	return iptables.run(params...)
}

// Check whether a rule matching the specification does exist in the selected chain.
// This command uses the same logic as -D to find a matching entry,
// but does not alter the existing iptables configuration and uses its exit code to indicate success or failure.
func (iptables *IPTables) Check(table, chain string, rulespec ...string) error {
	params := append([]string{"-t", table, "-C", chain}, rulespec...)

	return iptables.run(params...)
}

// Create a new user-defined chain by the given name. There must be no target of that name already.
func (iptables *IPTables) NewChain(table, chain string) error {
	if IsBuiltInChain(table, chain) {
		return fmt.Errorf("%s is a Built-in chain", chain)
	}

	params := []string{"-t", table, "-N", chain}

	return iptables.run(params...)
}

// Rename the user specified chain to the user supplied name.
// This is cosmetic, and has no effect on the structure of the table.
func (iptables *IPTables) RenameChain(table, oldChain, newChain string) error {
	if IsBuiltInChain(table, newChain) {
		return fmt.Errorf("%s is a Built-in chain", newChain)
	}

	params := []string{"-t", table, "-E", oldChain, newChain}

	return iptables.run(params...)
}

// Delete every non-builtin chain in the table.
// There must be no references to the chain.
// If there are, you must delete or replace the referring rules before the chain can be deleted.
// The chain must be empty, i.e. not contain any rules.
func (iptables *IPTables) DeleteChains(table string) error {
	params := []string{"-t", table, "-X"}

	return iptables.run(params...)
}

// Delete the optional user-defined chain specified.
// There must be no references to the chain.
// If there are, you must delete or replace the referring rules before the chain can be deleted.
// The chain must be empty, i.e. not contain any rules.
func (iptables *IPTables) DeleteChain(table, chain string) error {
	if IsBuiltInChain(table, chain) {
		return fmt.Errorf("%s is a Built-in chain", chain)
	}

	params := []string{"-t", table, "-X", chain}

	return iptables.run(params...)
}

func IsBuiltInChain(table, chain string) bool {
	result := false

	for t, chains := range BuiltInChains {
		if table == t {
			for _, c := range chains {
				if chain == c {
					result = true

					break
				}
			}

			break
		}
	}

	return result
}

func (iptables *IPTables) run(args ...string) error {
	var stderr bytes.Buffer

	cmd := exec.Command(iptables.Binary, args...)
	cmd.Stderr = &stderr

	if err := cmd.Run() ; err != nil {
		return fmt.Errorf(stderr.String())
	}

	return nil
}

func (iptables *IPTables) runList(table string, opts *ListOptions, args ...string) (map[ListOutputChain][]ListOutputRule, error) {
	var (
		reChain = regexp.MustCompile(`^Chain (.*) \(.*\)$`)
		reChainRulesHeader = regexp.MustCompile(`^\s*[num|pkts|target]`)

	)

	cmd := exec.Command(iptables.Binary, args...)
	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating StdoutPipe for Cmd", err)
		os.Exit(1)
	}

	err = cmd.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error starting Cmd", err)
		os.Exit(1)
	}

	ListOutput = make(map[ListOutputChain][]ListOutputRule)

	rChain := ListOutputChain{}
	scanner := bufio.NewScanner(cmdReader)
	for scanner.Scan() {
		chain := reChain.FindStringSubmatch(scanner.Text())
		if len(chain) > 0 {
			rChain = opts.CreateListChain(table, chain[1], scanner.Text())

			continue
		}

		if reChainRulesHeader.MatchString(scanner.Text()) || scanner.Text() == "" {
			continue
		}

		rRule := opts.CreateListRule(scanner.Text())

		ListOutput[rChain] = append(ListOutput[rChain], rRule)
	}

	err = cmd.Wait()
	if err != nil {
		return nil, err
	}

	return ListOutput, nil
}

func (opts *ListOptions) CreateListChain(table, chain, line string) ListOutputChain {
	var (
		reChainNoVerbose = regexp.MustCompile(`^Chain (.*) \(policy\s*(.*)\)$`)
		reChainVerbose = regexp.MustCompile(`^Chain (.*) \(policy\s*(.*)\s+([0-9]+)\s+packets,\s+([0-9]+)\s*bytes\)$`)
		reChainUser = regexp.MustCompile(`^Chain (.*) \(([0-9]+)\sreferences\)$`)
	)

	rChain := ListOutputChain{}
	rChain.Name = chain

	if IsBuiltInChain(table, chain) {
		if opts.Verbose {
			chaindata := reChainVerbose.FindStringSubmatch(line)

			rChain.Policy = chaindata[2]
			rChain.Packets = chaindata[3]
			rChain.Bytes = chaindata[4]
		} else {
			chaindata := reChainNoVerbose.FindStringSubmatch(line)
			rChain.Policy = chaindata[2]
		}

		rChain.BuiltIn = true
	} else {
		chaindata := reChainUser.FindStringSubmatch(line)
		ref, _ := strconv.Atoi(chaindata[2])

		rChain.BuiltIn = false
		rChain.Reference = ref
	}

	return rChain
}

func (opts *ListOptions) CreateListRule(line string) ListOutputRule {
	var (
		reRule = regexp.MustCompile(`^\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(.+)$`)
		reRuleVerbose = regexp.MustCompile(`^\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(.+)$`)
		reRuleLN = regexp.MustCompile(`^\s*([0-9]+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(.+)$`)
		reRuleVerboseAndLN = regexp.MustCompile(`^\s*([0-9]+)\s+(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(.+)$`)
	)

	if opts.Verbose && opts.LineNumbers {
		rule := reRuleVerboseAndLN.FindStringSubmatch(line)
		num, _ := strconv.Atoi(rule[1])
		pkts, _ := strconv.Atoi(rule[2])
		return ListOutputRule{
			Num: num,
			Pkts: pkts,
			Bytes: rule[3],
			Target: rule[4],
			Prot: rule[5],
			Opt: rule[6],
			In: rule[7],
			Out: rule[8],
			Source: rule[9],
			Destination: rule[10],
			Other: rule[11],
		}
	} else if opts.Verbose && ! opts.LineNumbers {
		rule := reRuleVerbose.FindStringSubmatch(line)
		pkts, _ := strconv.Atoi(rule[1])
		return ListOutputRule{
			Pkts: pkts,
			Bytes: rule[2],
			Target: rule[3],
			Prot: rule[4],
			Opt: rule[5],
			In: rule[6],
			Out: rule[7],
			Source: rule[8],
			Destination: rule[9],
			Other: rule[10],
		}
	} else if ! opts.Verbose && opts.LineNumbers {
		rule := reRuleLN.FindStringSubmatch(line)
		num, _ := strconv.Atoi(rule[1])
		return ListOutputRule{
			Num: num,
			Target: rule[2],
			Prot: rule[3],
			Opt: rule[4],
			Source: rule[5],
			Destination: rule[6],
			Other: rule[7],
		}
	} else {
		rule := reRule.FindStringSubmatch(line)
		return ListOutputRule{
			Target: rule[1],
			Prot: rule[2],
			Opt: rule[3],
			Source: rule[4],
			Destination: rule[5],
			Other: rule[6],
		}
	}
}
