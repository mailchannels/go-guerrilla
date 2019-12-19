package rfc5321

// Parse RFC5321 productions, no regex

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"unicode"
)

// Parse Email Addresses according to https://tools.ietf.org/html/rfc5321
type ParserUTF struct {
	accept     bytes.Buffer
	buf        []rune
	PathParams [][]string
	ADL        []string
	LocalPart  string
	Domain     string
	pos        int
	NullPath   bool
	ch         rune
}

func NewParserUTF(buf []rune) *ParserUTF {
	s := new(ParserUTF)
	s.buf = buf
	s.pos = -1
	return s
}

func (s *ParserUTF) Reset() {
	s.buf = s.buf[:0]
	if s.pos != -1 {
		s.pos = -1
		s.ADL = nil
		s.PathParams = nil
		s.NullPath = false
		s.LocalPart = ""
		s.Domain = ""
		s.accept.Reset()
	}
}

func (s *ParserUTF) set(input []rune) {
	s.Reset()
	s.buf = input
}

func (s *ParserUTF) next() rune {
	s.pos++
	if s.pos < len(s.buf) {
		s.ch = s.buf[s.pos]
		return s.ch
	}
	return 0
}

func (s *ParserUTF) peek() rune {
	if s.pos+1 < len(s.buf) {
		return s.buf[s.pos+1]
	}
	return 0
}

func (s *ParserUTF) reversePath() (err error) {
	if s.peek() == ' ' {
		s.next() // tolerate a space at the front
	}
	if i := bytes.Index([]byte(string(s.buf[s.pos+1:])), []byte{'<', '>'}); i == 0 {
		s.NullPath = true
		return nil
	}
	if err = s.path(); err != nil {
		return err
	}
	return nil
}

func (s *ParserUTF) forwardPath() (err error) {
	if s.peek() == ' ' {
		s.next() // tolerate a space at the front
	}
	if i := bytes.Index(bytes.ToLower([]byte(string(s.buf[s.pos+1:]))), []byte(postmasterPath)); i == 0 {
		s.LocalPart = postmasterLocalPart
		return nil
	}
	if err = s.path(); err != nil {
		return err
	}
	return nil
}

//MailFrom accepts the following syntax: Reverse-path [SP Mail-parameters] CRLF
func (s *ParserUTF) MailFrom(input []rune) (err error) {
	s.set(input)
	if err := s.reversePath(); err != nil {
		return err
	}
	s.next()
	if p := s.next(); p == ' ' {
		// parse Rcpt-parameters
		// The optional <mail-parameters> are associated with negotiated SMTP
		//  service extensions
		if tup, err := s.parameters(); err != nil {
			return errors.New("param parse error")
		} else if len(tup) > 0 {
			s.PathParams = tup
		}
	}
	return nil
}

//RcptTo accepts the following syntax: ( "<Postmaster@" Domain ">" / "<Postmaster>" /
//                  Forward-path ) [SP Rcpt-parameters] CRLF
func (s *ParserUTF) RcptTo(input []rune) (err error) {
	s.set(input)
	if err := s.forwardPath(); err != nil {
		return err
	}
	s.next()
	if p := s.next(); p == ' ' {
		// parse Rcpt-parameters
		if tup, err := s.parameters(); err != nil {
			return errors.New("param parse error")
		} else if len(tup) > 0 {
			s.PathParams = tup
		}
	}
	return nil
}

// esmtp-param *(SP esmtp-param)
func (s *ParserUTF) parameters() ([][]string, error) {
	params := make([][]string, 0)
	for {
		if result, err := s.param(); err != nil {
			return params, err
		} else {
			params = append(params, result)
		}
		if p := s.next(); p != ' ' {
			return params, nil
		}
	}
}

func isESMTPValueRune(c rune) bool {
	if ('!' <= c && c <= '<') ||
		('>' <= c && c <= '~') {
		return true
	}
	return false
}

// esmtp-param    = esmtp-keyword ["=" esmtp-value]
// esmtp-keyword  = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
// esmtp-value    = 1*(%d33-60 / %d62-126)
func (s *ParserUTF) param() (result []string, err error) {
	state := 0
	var key, value string
	defer func() {
		result = append(result, key, value)
		s.accept.Reset()
	}()
	for c := s.next(); ; c = s.next() {
		switch state {
		case 0:
			// first char must be let-dig
			if !isLetterOrDigit(c) {
				return result, errors.New("parse error")
			}
			// accept
			s.accept.WriteRune(c)
			state = 1
		case 1:
			// *(ALPHA / DIGIT / "-")
			if !isLetterOrDigit(c) {
				if c == '=' {
					key = s.accept.String()
					s.accept.Reset()
					state = 2
					continue
				} else if c == '-' {
					// cannot have - at the end of a keyword
					if p := s.peek(); !isLetterOrDigit(p) && p != '-' {
						return result, errors.New("parse error")
					}
					s.accept.WriteRune(c)
					continue

				}
				key = s.accept.String()
				return result, nil
			}
			s.accept.WriteRune(c)
		case 2:
			// start of value, must match at least 1
			if !isESMTPValueRune(c) {
				return result, errors.New("parse error")
			}
			s.accept.WriteRune(c)
			if !isESMTPValueRune(s.peek()) {
				value = s.accept.String()
				return result, nil
			}
			state = 3
		case 3:
			// 1*(%d33-60 / %d62-126)
			s.accept.WriteRune(c)
			if !isESMTPValueRune(s.peek()) {
				value = s.accept.String()
				return result, nil
			}
		}
	}
}

// "<" [ A-d-l ":" ] Mailbox ">"
func (s *ParserUTF) path() (err error) {
	if s.next() == '<' && s.peek() == '@' {
		if err = s.adl(); err == nil {
			s.next()
			if s.ch != ':' {
				return errors.New("syntax error")
			}
		}
	}
	if err = s.mailbox(); err != nil {
		return err
	}
	if p := s.peek(); p != '>' {
		return errors.New("missing closing >")
	}
	return nil
}

// At-domain *( "," At-domain )
func (s *ParserUTF) adl() error {
	for {
		if err := s.atDomain(); err != nil {
			return err
		}
		s.ADL = append(s.ADL, s.accept.String())
		s.accept.Reset()
		if s.peek() != ',' {
			break
		}
		s.next()
	}
	return nil
}

// At-domain = "@" Domain
func (s *ParserUTF) atDomain() error {
	if s.next() == '@' {
		s.accept.WriteByte('@')
		return s.domain()
	}
	return errors.New("syntax error")
}

// sub-domain *("." sub-domain)
func (s *ParserUTF) domain() error {
	for {
		if err := s.subdomain(); err != nil {
			return err
		}
		if p := s.peek(); p != '.' {
			if p != ':' && p != ',' && p != '>' && p != 0 {
				return errors.New("domain parse error")
			}

			break
		}
		s.accept.WriteRune(s.next())
	}
	return nil
}

// Let-dig [Ldh-str]
func (s *ParserUTF) subdomain() error {
	state := 0
	for c := s.next(); ; c = s.next() {
		switch state {
		case 0:
			p := s.peek()
			if isLetterOrDigit(c) {
				s.accept.WriteRune(c)
				if !isLetterOrDigit(p) && p != '-' {
					return nil
				}
				state = 1
				continue
			}
			return errors.New("parse err")
		case 1:
			p := s.peek()
			if isLetterOrDigit(c) || c == '-' {
				s.accept.WriteRune(c)
			}
			if !isLetterOrDigit(p) && p != '-' {
				if c == '-' {
					return errors.New("parse err")
				}
				return nil
			}
		}
	}
}

// Local-part "@" ( Domain / address-literal )
func (s *ParserUTF) mailbox() error {
	defer func() {
		if s.accept.Len() > 0 {
			s.Domain = s.accept.String()
			s.accept.Reset()
		}
	}()
	err := s.localPart()
	if err != nil {
		return err
	}
	if s.ch != '@' {
		return errors.New("@ expected as part of mailbox")
	}
	if p := s.peek(); p == '[' {
		return s.addressLiteral()
	} else {
		return s.domain()
	}
}

// "[" ( IPv4-address-literal /
//                    IPv6-address-literal /
//                    General-address-literal ) "]"
func (s *ParserUTF) addressLiteral() error {
	ch := s.next()
	if ch == '[' {
		p := s.peek()
		var err error
		if p == 'I' || p == 'i' {
			for i := 0; i < 5; i++ {
				s.next() // IPv6:
			}
			err = s.ipv6AddressLiteral()
		} else if p >= 48 && p <= 57 {
			err = s.ipv4AddressLiteral()
		}
		if err != nil {
			return err
		}
		if s.ch != ']' {
			return errors.New("] expected for address literal")
		}
		return nil
	}
	return nil
}

// Snum 3("."  Snum)
func (s *ParserUTF) ipv4AddressLiteral() error {
	for i := 0; i < 4; i++ {
		if err := s.snum(); err != nil {
			return err
		}
		if s.ch != '.' {
			break
		}
		s.accept.WriteRune(s.ch)
	}
	return nil
}

// 1*3DIGIT
// representing a decimal integer
// value accept the range 0 through 255
func (s *ParserUTF) snum() error {
	state := 0
	var num bytes.Buffer
	for i := 4; i > 0; i-- {
		c := s.next()
		if state == 0 {
			if !(c >= 48 && c <= 57) {
				return errors.New("parse error")
			} else {
				num.WriteRune(s.ch)
				s.accept.WriteRune(s.ch)
				state = 1
				continue
			}
		}
		if state == 1 {
			if !(c >= 48 && c <= 57) {
				if v, err := strconv.Atoi(num.String()); err != nil {
					return err
				} else if v >= 0 && v <= 255 {
					return nil
				} else {
					return errors.New("invalid ipv4")
				}
			} else {
				num.WriteRune(s.ch)
				s.accept.WriteRune(s.ch)
			}
		}
	}
	return errors.New("too many digits")
}

//IPv6:" IPv6-addr
func (s *ParserUTF) ipv6AddressLiteral() error {
	var ip bytes.Buffer
	for c := s.next(); ; c = s.next() {
		if !(c >= 48 && c <= 57) &&
			!(c >= 65 && c <= 70) &&
			!(c >= 97 && c <= 102) &&
			c != ':' && c != '.' {
			ipstr := ip.String()
			if v := net.ParseIP(ipstr); v != nil {
				s.accept.WriteString(ipstr)
				return nil
			}
			return errors.New("invalid ipv6")
		} else {
			ip.WriteRune(c)
		}
	}
}

// Dot-string / Quoted-string
func (s *ParserUTF) localPart() error {
	defer func() {
		if s.accept.Len() > 0 {
			s.LocalPart = s.accept.String()
			s.accept.Reset()
		}
	}()
	p := s.peek()
	if p == '"' {
		return s.quotedString()
	} else {
		return s.dotString()
	}
}

// DQUOTE *QcontentSMTP DQUOTE
func (s *ParserUTF) quotedString() error {
	if s.next() == '"' {
		if err := s.QcontentSMTP(); err != nil {
			return err
		}
		if s.ch != '"' {
			return errors.New("quoted string not closed")
		} else {
			// accept the "
			s.next()
		}
	}
	return nil
}

// qtextSMTP / quoted-pairSMTP
// quoted-pairSMTP = %d92 %d32-126
// qtextSMTP = %d32-33 / %d35-91 / %d93-126
func (s *ParserUTF) QcontentSMTP() error {
	state := 0
	for {
		ch := s.next()
		switch state {
		case 0:
			if ch == '\\' {
				state = 1
				s.accept.WriteRune(ch)
				continue
			} else if ch == 32 || ch == 33 ||
				unicode.IsLetter(ch) ||
				(ch >= 35 && ch <= 91) ||
				(ch >= 93 && ch <= 126) {
				s.accept.WriteRune(ch)
				continue
			}
			return nil
		case 1:
			// escaped character state
			if unicode.IsLetter(ch) || (ch >= 32 && ch <= 126) {
				s.accept.WriteRune(ch)
				state = 0
				continue
			} else {
				return errors.New("non-printable character found")
			}
		}
	}
}

//Dot-string     = Atom *("."  Atom)
func (s *ParserUTF) dotString() error {
	for {
		if err := s.atom(); err != nil {
			return err
		}
		if s.ch != '.' {
			break
		}
		s.accept.WriteRune(s.ch)
	}
	return nil
}

// 1*atext
func (s *ParserUTF) atom() error {
	state := 0
	for {
		if state == 0 {
			if !s.isAtext(s.next()) {
				return errors.New("parse error")
			} else {
				s.accept.WriteRune(s.ch)
				state = 1
				continue
			}
		}
		if state == 1 {
			if !s.isAtext(s.next()) {
				return nil
			} else {
				s.accept.WriteRune(s.ch)
			}
		}
	}
}

/*

Dot-string     = Atom *("."  Atom)

Atom           = 1*atext

atext           =       ALPHA / DIGIT / ; Any character except controls,
                        "!" / "#" /     ;  SP, and specials.
                        "$" / "%" /     ;  Used for atoms
                        "&" / "'" /
                        "*" / "+" /
                        "-" / "/" /
                        "=" / "?" /
                        "^" / "_" /
                        "`" / "{" /
                        "|" / "}" /
                        "~"

*/

func (s *ParserUTF) isAtext(c rune) bool {
	if ('0' <= c && c <= '9') ||
		('A' <= c && c <= 'z') ||
		unicode.IsLetter(c) ||
		c == '!' || c == '#' ||
		c == '$' || c == '%' ||
		c == '&' || c == '\'' ||
		c == '*' || c == '+' ||
		c == '-' || c == '/' ||
		c == '=' || c == '?' ||
		c == '^' || c == '_' ||
		c == '`' || c == '{' ||
		c == '|' || c == '}' ||
		c == '~' {
		return true
	}
	return false
}

func isLetterOrDigit(c rune) bool {
	if ('0' <= c && c <= '9') ||
		unicode.IsLetter(c) {
		return true
	}
	return false
}
