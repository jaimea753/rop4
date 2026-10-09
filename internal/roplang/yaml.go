package roplang

import (
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/reverseame/rop4/internal/operation"
	"gopkg.in/yaml.v3"
)

//go:embed roplang/*.yaml
var catalogFS embed.FS

var opKeyRE = regexp.MustCompile(`^op\d+$`)

// loadOps reads and parses every embedded catalog file into OperationDefs.
func (p *Parser) loadOps() ([]*operation.OperationDef, error) {
	entries, err := catalogFS.ReadDir("roplang")
	if err != nil {
		return nil, &ParserError{Msg: fmt.Sprintf("roplang catalog: %v", err)}
	}
	// Sort filenames for deterministic operation ordering.
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var ret []*operation.OperationDef
	for _, name := range names {
		data, err := catalogFS.ReadFile("roplang/" + name)
		if err != nil {
			return nil, &ParserError{Msg: fmt.Sprintf("%s: %v", name, err)}
		}
		var root map[string]yaml.Node
		if err := yaml.Unmarshal(data, &root); err != nil {
			return nil, &ParserError{Msg: fmt.Sprintf("%s: %v", name, err)}
		}
		// A file may define several ops; preserve a stable order by key.
		keys := make([]string, 0, len(root))
		for k := range root {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, op := range keys {
			node := root[op]
			defn, err := p.parseOp(op, &node)
			if err != nil {
				return nil, err
			}
			ret = append(ret, defn)
		}
	}
	return ret, nil
}

// childNode returns the value node for `key` in a mapping node (nil if absent).
func childNode(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// parseOp parses one operation definition in the multi-architecture format.
func (p *Parser) parseOp(op string, content *yaml.Node) (*operation.OperationDef, error) {
	var operands int
	if n := childNode(content, "operands"); n != nil {
		_ = n.Decode(&operands)
	}
	var dst, src []string
	if n := childNode(content, "dst"); n != nil {
		_ = n.Decode(&dst)
	}
	if n := childNode(content, "src"); n != nil {
		_ = n.Decode(&src)
	}
	defn := operation.NewOperationDef(op, operands, p.resolveRoles(dst), p.resolveRoles(src))

	archBlock := childNode(content, p.archFamily())
	if archBlock == nil {
		return defn, nil
	}
	if archBlock.Kind == yaml.MappingNode {
		// Availability marker instead of a realization list.
		available := true
		if n := childNode(archBlock, "available"); n != nil {
			_ = n.Decode(&available)
		}
		if !available {
			reason := ""
			if n := childNode(archBlock, "reason"); n != nil {
				_ = n.Decode(&reason)
			}
			defn.MarkUnavailable(reason)
		}
		return defn, nil
	}
	if archBlock.Kind == yaml.SequenceNode {
		for _, entry := range archBlock.Content {
			steps := entry
			if entry.Kind == yaml.MappingNode {
				steps = childNode(entry, "steps")
			}
			if steps == nil {
				continue
			}
			links, err := p.realizationLinks(steps)
			if err != nil {
				return nil, err
			}
			defn.AddRealization(links)
		}
	}
	return defn, nil
}

// realizationLinks translates the YAML steps of one realization into neutral
// link data.
func (p *Parser) realizationLinks(steps *yaml.Node) ([]operation.LinkData, error) {
	var links []operation.LinkData
	if steps.Kind != yaml.SequenceNode {
		return links, nil
	}
	for _, entry := range steps.Content {
		switch {
		case entry.Kind == yaml.SequenceNode:
			// Nested list: a single gadget with multiple instructions.
			var insns []operation.InsnData
			for _, s := range entry.Content {
				insns = append(insns, p.instructionData(s))
			}
			links = append(links, operation.LinkData{Gadget: insns})
		case entry.Kind == yaml.MappingNode && childNode(entry, "mnemonic") != nil:
			var writes, reads []string
			if n := childNode(entry, "writes"); n != nil {
				_ = n.Decode(&writes)
			}
			if n := childNode(entry, "reads"); n != nil {
				_ = n.Decode(&reads)
			}
			links = append(links, operation.LinkData{
				Gadget: []operation.InsnData{p.instructionData(entry)},
				Writes: p.resolveRoles(writes),
				Reads:  p.resolveRoles(reads),
			})
		case entry.Kind == yaml.MappingNode && childNode(entry, "operation") != nil:
			opName := childNode(entry, "operation").Value
			bindings := map[string]string{}
			for i := 0; i+1 < len(entry.Content); i += 2 {
				key := entry.Content[i].Value
				if opKeyRE.MatchString(key) {
					var v any
					_ = entry.Content[i+1].Decode(&v)
					bindings[key] = anyToStr(p.resolveAlias(v))
				}
			}
			links = append(links, operation.LinkData{OpRef: opName, Bindings: bindings})
		}
	}
	return links, nil
}

// instructionData extracts one instruction as neutral data: its mnemonic and
// its alias-resolved operands in positional (op1, op2, ...) order.
func (p *Parser) instructionData(step *yaml.Node) operation.InsnData {
	mnemonic := ""
	if n := childNode(step, "mnemonic"); n != nil {
		mnemonic = n.Value
	}
	type kv struct {
		num int
		val any
	}
	var kvs []kv
	for i := 0; i+1 < len(step.Content); i += 2 {
		key := step.Content[i].Value
		if opKeyRE.MatchString(key) {
			num, _ := strconv.Atoi(key[2:])
			var v any
			_ = step.Content[i+1].Decode(&v)
			kvs = append(kvs, kv{num, p.resolveAlias(v)})
		}
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].num < kvs[j].num })
	operands := make([]any, len(kvs))
	for i, e := range kvs {
		operands[i] = e.val
	}
	return operation.InsnData{Mnemonic: mnemonic, Operands: operands}
}

// anyToStr renders a resolved binding value as a string (bindings are strings).
func anyToStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}
