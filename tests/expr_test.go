package tests

import "fmt"
import "testing"
import "github.com/honeytrap/yara-parser/data"

func TestExpr(t *testing.T) {
	const rs = `rule FOR {
strings:
    $s1 = "abc"
condition:
	true or "false"
}`
	tree, err := parseRuleStr(rs)
	if err != nil {
		t.Fatalf(`Parsing failed: %s`, err)
	}
	cond := tree.Rules[0].Condition
	switch cond.Right.(data.Expression).Left.(type) {
	case data.RawString:
		fmt.Println("rs")
	case string:
		fmt.Println("s")
	default:
		fmt.Println("wtf")
	}
	fmt.Printf("%#v\n", cond.Right.(data.Expression).Left)
	if cond.Left.(data.Expression).Left != true || cond.Operator != "or" || cond.Right.(data.Expression).Left != false {
		t.Fatalf(`Unexpected parse tree`)
	}
}
