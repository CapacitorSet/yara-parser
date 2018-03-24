// Functions and methods for reserializing the JSON into YARA rules

package data

import (
	"fmt"
	"strings"
)

// Serialize for String returns a String as a string
func (s *String) Serialize() string {
	// Format string for:
	// `<identifier> = <encapsOpen> <text> <encapsClose> <modifiers>`
	format := "%s = %s%s%s %s"

	var (
		encapsOpen  string
		encapsClose string
	)
	switch s.Type {
	case TypeString:
		encapsOpen, encapsClose = `"`, `"`

	case TypeHexString:
		encapsOpen, encapsClose = "{", "}"

	case TypeRegex:
		encapsOpen = "/"
		var closeBuilder strings.Builder
		closeBuilder.WriteRune('/')
		if s.Modifiers.I {
			closeBuilder.WriteRune('i')
		}
		if s.Modifiers.S {
			closeBuilder.WriteRune('s')
		}
		encapsClose = closeBuilder.String()

	default:
		// TODO: panic or something
	}

	mods := s.Modifiers.Serialize()

	return fmt.Sprintf(format, s.ID, encapsOpen, s.Text, encapsClose, mods)
}

// Serialize for StringModifiers creates a space-sparated list of
// string modifiers, excluding the i and s which are appended to /regex/
func (m *StringModifiers) Serialize() string {
	const modsAvailable = 4
	modifiers := make([]string, 0, modsAvailable)
	if m.ASCII {
		modifiers = append(modifiers, "ascii")
	}
	if m.Wide {
		modifiers = append(modifiers, "wide")
	}
	if m.Nocase {
		modifiers = append(modifiers, "nocase")
	}
	if m.Fullword {
		modifiers = append(modifiers, "fullword")
	}
	return strings.Join(modifiers, " ")
}
