package rfc5321

import (
	"strings"
	"testing"
)

func TestParseParamUnicode(t *testing.T) {
	s := NewParserUTF([]rune("SIZE=2000"))
	params, err := s.param()
	if strings.Compare(params[0], "SIZE") != 0 {
		t.Error("SIZE ecpected")
	}
	if strings.Compare(params[1], "2000") != 0 {
		t.Error("2000 ecpected")
	}
	if err != nil {
		t.Error("error not expected ", err)
	}

	s = NewParserUTF([]rune("SI--ZE=2000 BODY=8BITMIME"))
	tup, err := s.parameters()
	if strings.Compare(tup[0][0], "SI--ZE") != 0 {
		t.Error("SI--ZE ecpected")
	}
	if strings.Compare(tup[0][1], "2000") != 0 {
		t.Error("2000 ecpected")
	}
	if strings.Compare(tup[1][0], "BODY") != 0 {
		t.Error("BODY expected", err)
	}
	if strings.Compare(tup[1][1], "8BITMIME") != 0 {
		t.Error("8BITMIME expected", err)
	}

	s = NewParserUTF([]rune("SI--ZE-=2000 BODY=8BITMIME")) // illegal - after ZE
	tup, err = s.parameters()
	if err == nil {
		t.Error("error was expected ")
	}
}

func TestParseRcptToUnicode(t *testing.T) {
	var s ParserUTF
	err := s.RcptTo([]rune("<Postmaster>"))
	if err != nil {
		t.Error("error not expected ", err)
	}

	err = s.RcptTo([]rune("<Postmaster@example.com>"))
	if err != nil {
		t.Error("error not expected ", err)
	}
	if s.LocalPart != "Postmaster" {
		t.Error("s.LocalPart should be: Postmaster")
	}

	err = s.RcptTo([]rune("<Postmaster@example.com> NOTIFY=SUCCESS,FAILURE"))
	if err != nil {
		t.Error("error not expected ", err)
	}

	//
}

func TestParseForwardPathUnicode(t *testing.T) {
	s := NewParserUTF([]rune("<@a,@b:user@[227.0.0.1>")) // missing ]
	err := s.forwardPath()
	if err == nil {
		t.Error("error expected ", err)
	}

	s = NewParserUTF([]rune("<@a,@b:user@[527.0.0.1>")) // ip out of range
	err = s.forwardPath()
	if err == nil {
		t.Error("error expected ", err)
	}

	// with a 'size' estmp param
	s = NewParserUTF([]rune("<ned@thor.innosoft.com> NOTIFY=FAILURE ORCPT=rfc822;Carol@Ivory.EDU"))
	err = s.forwardPath()
	if err != nil {
		t.Error("error not expected ", err)
	}

	// tolerate a space at the front
	s = NewParserUTF([]rune(" <ned@thor.innosoft.com>"))
	err = s.forwardPath()
	if err != nil {
		t.Error("error not expected ", err)
	}

	// tolerate a space at the front, invalid
	s = NewParserUTF([]rune(" <"))
	err = s.forwardPath()
	if err == nil {
		t.Error("error expected ", err)
	}

	// tolerate a space at the front, invalid
	s = NewParserUTF([]rune(" "))
	err = s.forwardPath()
	if err == nil {
		t.Error("error expected ", err)
	}

	// empty
	s = NewParserUTF([]rune(""))
	err = s.forwardPath()
	if err == nil {
		t.Error("error expected ", err)
	}

}

func TestParseReversePathUnicode(t *testing.T) {

	s := NewParserUTF([]rune("<@a,@b:user@d>"))
	err := s.reversePath()
	if err != nil {
		t.Error("error not expected ", err)
	}

	s = NewParserUTF([]rune("<@a,@b:user@d> param=some-value")) // includes a mail parameter
	err = s.reversePath()
	if err != nil {
		t.Error("error not expected ", err)
	}

	s = NewParserUTF([]rune("<@a,@b:user@[227.0.0.1]>"))
	err = s.reversePath()
	if err != nil {
		t.Error("error not expected ", err)
	}

	s = NewParserUTF([]rune("<>"))
	err = s.reversePath()
	if err != nil {
		t.Error("error not expected ", err)
	}

	s = NewParserUTF([]rune(""))
	err = s.reversePath()
	if err == nil {
		t.Error("error  expected ", err)
	}

	s = NewParserUTF([]rune("test@rcample.com"))
	err = s.reversePath()
	if err == nil {
		t.Error("error expected ", err)
	}

	s = NewParserUTF([]rune("<@ghg;$7@65"))
	err = s.reversePath()
	if err == nil {
		t.Error("error  expected ", err)
	}

	// tolerate a space at the front
	s = NewParserUTF([]rune(" <>"))
	err = s.reversePath()
	if err != nil {
		t.Error("error not expected ", err)
	}

	// tolerate a space at the front, invalid
	s = NewParserUTF([]rune(" <"))
	err = s.reversePath()
	if err == nil {
		t.Error("error expected ", err)
	}

	// tolerate a space at the front, invalid
	s = NewParserUTF([]rune(" "))
	err = s.reversePath()
	if err == nil {
		t.Error("error expected ", err)
	}

	// empty
	s = NewParserUTF([]rune(" "))
	err = s.reversePath()
	if err == nil {
		t.Error("error expected ", err)
	}
}

func TestParseIpv6AddressUnicode(t *testing.T) {
	s := NewParserUTF([]rune("2001:0000:3238:DFE1:0063:0000:0000:FEFB"))
	err := s.ipv6AddressLiteral()
	if s.accept.String() != "2001:0000:3238:DFE1:0063:0000:0000:FEFB" {
		t.Error("expected 2001:0000:3238:DFE1:0063:0000:0000:FEFB, got:", s.accept.String())
	}
	if err != nil {
		t.Error("error not expected ", err)
	}
	s = NewParserUTF([]rune("2001:3238:DFE1:6323:FEFB:2536:1.2.3.2"))
	err = s.ipv6AddressLiteral()
	if s.accept.String() != "2001:3238:DFE1:6323:FEFB:2536:1.2.3.2" {
		t.Error("expected 2001:3238:DFE1:6323:FEFB:2536:1.2.3.2, got:", s.accept.String())
	}
	if err != nil {
		t.Error("error not expected ", err)
	}

	s = NewParserUTF([]rune("2001:0000:3238:DFE1:63:0000:0000:FEFB"))
	err = s.ipv6AddressLiteral()
	if s.accept.String() != "2001:0000:3238:DFE1:63:0000:0000:FEFB" {
		t.Error("expected 2001:0000:3238:DFE1:63:0000:0000:FEFB, got:", s.accept.String())
	}
	if err != nil {
		t.Error("error not expected ", err)
	}

	s = NewParserUTF([]rune("2001:0000:3238:DFE1:63::FEFB"))
	err = s.ipv6AddressLiteral()
	if s.accept.String() != "2001:0000:3238:DFE1:63::FEFB" {
		t.Error("expected 2001:0000:3238:DFE1:63::FEFB, got:", s.accept.String())
	}
	if err != nil {
		t.Error("error not expected ", err)
	}

	s = NewParserUTF([]rune("2001:0:3238:DFE1:63::FEFB"))
	err = s.ipv6AddressLiteral()
	if s.accept.String() != "2001:0:3238:DFE1:63::FEFB" {
		t.Error("expected 2001:0:3238:DFE1:63::FEFB, got:", s.accept.String())
	}
	if err != nil {
		t.Error("error not expected ", err)
	}

	s = NewParserUTF([]rune("g001:0:3238:DFE1:63::FEFB"))
	err = s.ipv6AddressLiteral()
	if s.accept.String() != "" {
		t.Error("expected \"\", got:", s.accept.String())
	}
	if err == nil {
		t.Error("error expected ", err)
	}

	s = NewParserUTF([]rune("g001:0:3238:DFE1::63::FEFB"))
	err = s.ipv6AddressLiteral()
	if s.accept.String() != "" {
		t.Error("expected \"\", got:", s.accept.String())
	}
	if err == nil {
		t.Error("error expected ", err)
	}
}

func TestParseIpv4AddressUnicode(t *testing.T) {
	s := NewParserUTF([]rune("0.0.0.255"))
	err := s.ipv4AddressLiteral()
	if s.accept.String() != "0.0.0.255" {
		t.Error("expected 0.0.0.255, got:", s.accept.String())
	}
	if err != nil {
		t.Error("error not expected ", err)
	}

	s = NewParserUTF([]rune("0.0.0.256"))
	err = s.ipv4AddressLiteral()
	if s.accept.String() != "0.0.0.256" {
		t.Error("expected 0.0.0.256, got:", s.accept.String())
	}
	if err == nil {
		t.Error("error expected ", err)
	}

}

func TestParseMailBoxBadUnicode(t *testing.T) {

	// must be quoted
	s := NewParserUTF([]rune("Abc\\@def@example.com"))
	err := s.mailbox()

	if err == nil {
		t.Error("error expected")
	}

	// must be quoted
	s = NewParserUTF([]rune("Fred\\ Bloggs@example.com"))
	err = s.mailbox()

	if err == nil {
		t.Error("error expected")
	}
}

func TestParseMailboxUnicode(t *testing.T) {

	s := NewParserUTF([]rune("jsmith@[IPv6:2001:db8::1]"))
	err := s.mailbox()
	if s.Domain != "2001:db8::1" {
		t.Error("expected domain:2001:db8::1, got:", s.Domain)
	}
	if err != nil {
		t.Error("error not expected ")
	}

	s = NewParserUTF([]rune("\"qu\\{oted\"@test.com"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}

	s = NewParserUTF([]rune("LéaAubertnu@test.com"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}

	s = NewParserUTF([]rune("\"qu\\{oted\"@[127.0.0.1]"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}

	s = NewParserUTF([]rune("jsmith@[IPv6:2001:db8::1]"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}

	s = NewParserUTF([]rune("Joe.\\Blow@example.com"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("\"Abc@def\"@example.com"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("\"Fred Bloggs\"@example.com"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("customer/department=shipping@example.com"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("$A12345@example.com"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("!def!xyz%abc@example.com"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("_somename@example.com"))
	err = s.mailbox()
	if err != nil {
		t.Error("error not expected ")
	}

}

func TestParseLocalPartUnicode(t *testing.T) {
	s := NewParserUTF([]rune("\"qu\\{oted\""))
	err := s.localPart()
	if s.LocalPart != "qu\\{oted" {
		t.Error("expected qu\\{oted, got:", s.LocalPart)
	}
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("dot.string"))
	err = s.localPart()
	if s.LocalPart != "dot.string" {
		t.Error("expected dot.string, got:", s.LocalPart)
	}
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("dot.st!ring"))
	err = s.localPart()
	if s.LocalPart != "dot.st!ring" {
		t.Error("expected dot.st!ring, got:", s.LocalPart)
	}
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("dot..st!ring")) // fail
	err = s.localPart()

	if err == nil {
		t.Error("error expected ")
	}
}

func TestParseQuotedStringUnicode(t *testing.T) {
	s := NewParserUTF([]rune("\"qu\\ oted\""))
	err := s.quotedString()
	if s.accept.String() != "qu\\ oted" {
		t.Error("Expected qu\\ oted, got:", s.accept.String())
	}
	if err != nil {
		t.Error("error not expected ")
	}

	s = NewParserUTF([]rune("\"@\""))
	err = s.quotedString()
	if s.accept.String() != "@" {
		t.Error("Expected @, got:", s.accept.String())
	}
	if err != nil {
		t.Error("error not expected ")
	}
}

func TestParseDotStringUnicode(t *testing.T) {

	s := NewParserUTF([]rune("Joe..\\\\Blow"))
	err := s.dotString()
	if err == nil {
		t.Error("error expected ")
	}

	s = NewParserUTF([]rune("Joe.\\\\Blow"))
	err = s.dotString()
	if s.accept.String() != "Joe.\\\\Blow" {
		t.Error("Expected Joe.\\\\Blow, got:", s.accept.String())
	}
	if err != nil {
		t.Error("error not expected ")
	}
}

func TestParsePathUnicode(t *testing.T) {
	s := NewParserUTF([]rune("<foo>")) // requires @
	err := s.path()
	if err == nil {
		t.Error("error expected ")
	}
	s = NewParserUTF([]rune("<@example.com,@test.com:foo@example.com>"))
	err = s.path()
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("<@example.com>")) // no mailbox
	err = s.path()
	if err == nil {
		t.Error("error expected ")
	}

	s = NewParserUTF([]rune("<test@example.com	1")) // no closing >
	err = s.path()
	if err == nil {
		t.Error("error expected ")
	}
}

func TestParseADLUnicode(t *testing.T) {
	s := NewParserUTF([]rune("@example.com,@test.com"))
	err := s.adl()
	if err != nil {
		t.Error("error not expected ")
	}
}

func TestParseAtDomainUnicode(t *testing.T) {
	s := NewParserUTF([]rune("@example.com"))
	err := s.atDomain()
	if err != nil {
		t.Error("error not expected ")
	}
}

func TestParseDomainUnicode(t *testing.T) {

	s := NewParserUTF([]rune("a"))
	err := s.domain()
	if err != nil {
		t.Error("error not expected ")
	}

	s = NewParserUTF([]rune("a.com.gov"))
	err = s.domain()
	if err != nil {
		t.Error("error not expected ")
	}

	s = NewParserUTF([]rune("wrong-.com"))
	err = s.domain()
	if err == nil {
		t.Error("error was expected ")
	}
	s = NewParserUTF([]rune("wrong."))
	err = s.domain()
	if err == nil {
		t.Error("error was expected ")
	}
}

func TestParseSubDomainUnicode(t *testing.T) {

	s := NewParserUTF([]rune("a"))
	err := s.subdomain()
	if err != nil {
		t.Error("error not expected ")
	}
	s = NewParserUTF([]rune("-a"))
	err = s.subdomain()
	if err == nil {
		t.Error("error was expected ")
	}
	s = NewParserUTF([]rune("a--"))
	err = s.subdomain()
	if err == nil {
		t.Error("error was expected ")
	}
	s = NewParserUTF([]rune("a--"))
	err = s.subdomain()
	if err == nil {
		t.Error("error was expected ")
	}
	s = NewParserUTF([]rune("a--b"))
	err = s.subdomain()
	if err != nil {
		t.Error("error was not expected ")
	}

	// although a---b looks like an illegal subdomain, it is rfc5321 grammar spec
	s = NewParserUTF([]rune("a---b"))
	err = s.subdomain()
	if err != nil {
		t.Error("error was not expected ")
	}

	s = NewParserUTF([]rune("abc"))
	err = s.subdomain()
	if err != nil {
		t.Error("error was not expected ")
	}

	s = NewParserUTF([]rune("a-b-c"))
	err = s.subdomain()
	if err != nil {
		t.Error("error was not expected ")
	}

}
func TestParseUnicode(t *testing.T) {

	s := NewParserUTF([]rune("<"))
	err := s.reversePath()
	if err == nil {
		t.Error("< expected parse error")
	}

	// the @ needs to be quoted
	s = NewParserUTF([]rune("<@m.conm@test.com>"))
	err = s.reversePath()
	if err == nil {
		t.Error("expected parse error", err)
	}

	s = NewParserUTF([]rune("<\"@m.conm\"@test.com>"))
	err = s.reversePath()
	if err != nil {
		t.Error("not expected parse error", err)
	}

	s = NewParserUTF([]rune("<m-m.conm@test.com>"))
	err = s.reversePath()
	if err != nil {
		t.Error("not expected parse error")
	}

	s = NewParserUTF([]rune("<@test:user@test.com>"))
	err = s.reversePath()
	if err != nil {
		t.Error("not expected parse error")
	}
	s = NewParserUTF([]rune("<@test,@test2:user@test.com>"))
	err = s.reversePath()
	if err != nil {
		t.Error("not expected parse error")
	}

}
