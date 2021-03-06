// adapter.go provides an adapter for a flexgo lexer to work
// with a goyacc parser

package grammar

import (
	"fmt"
	"io"

	"github.com/honeytrap/yara-parser/data"
)

var errParser error

func init() {
	xxErrorVerbose = true
}

// Parse takes an input source and an output and initiates parsing
func Parse(input io.Reader, output io.Writer) (rs data.RuleSet, err error) {
	defer recoverParse(&err)

	// "Reset" the global ParsedRuleset
	ParsedRuleset = data.RuleSet{}

	lexer := Lexer{
		lexer: *NewScanner(),
	}
	lexer.lexer.In = input
	lexer.lexer.Out = output

	result := xxParse(&lexer)
	if result != 0 {

		err = fmt.Errorf(`Parser result: "%d" %s`, result, errParser)
	}

	rs = ParsedRuleset

	return
}

// Lexer is an adapter that fits the flexgo lexer ("Scanner") into goyacc
type Lexer struct {
	lexer Scanner
}

// Lex provides the interface expected by the goyacc parser.
// It sets the global yylval pointer (defined in the lexer file)
// to the one passed as an argument so that the parser actions
// can make use of it.
func (l *Lexer) Lex(lval *xxSymType) int {
	yylval = lval
	return l.lexer.Lex().(int)
}

// Error satisfies the interface expected of the goyacc parser.
// Here, it simply writes the error to stdout.
func (l *Lexer) Error(e string) {
	errParser = fmt.Errorf(`grammar: lexical error @%d: "%s"`,
		l.lexer.Lineno, e)
}
