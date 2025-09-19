//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package compiler

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"unicode"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/ast"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/mpa"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/types"
)

// TokenType specifies input token types.
type TokenType int

// Input tokens.
const (
	TIdentifier TokenType = 256 + iota
	TConstant
	TSymPackage
	TSymImport
	TSymFunc
	TSymIf
	TSymElse
	TSymBreak
	TSymContinue
	TSymGoto
	TSymReturn
	TSymStruct
	TSymVar
	TSymConst
	TSymType
	TSymFor
	TSymRange
	TSymNil
	TDefAssign
	TMultEq
	TDivEq
	TLshiftEq
	TLshift
	TRshiftEq
	TRshift
	TPlusPlus
	TPlusEq
	TMinusMinus
	TMinusEq
	TOrEq
	TXorEq
	TAndEq
	TLt
	TLe
	TGt
	TGe
	TEq
	TNeq
	TAnd
	TOr
	TBitClear
	TSend
)

var tokenTypes = map[TokenType]string{
	TIdentifier:  "identifier",
	TConstant:    "constant",
	TSymPackage:  "package",
	TSymImport:   "import",
	TSymFunc:     "func",
	TSymIf:       "if",
	TSymElse:     "else",
	TSymBreak:    "break",
	TSymContinue: "continue",
	TSymGoto:     "goto",
	TSymReturn:   "return",
	TSymStruct:   "struct",
	TSymVar:      "var",
	TSymConst:    "const",
	TSymType:     "type",
	TSymFor:      "for",
	TSymRange:    "range",
	TSymNil:      "nil",
	TDefAssign:   ":=",
	TMultEq:      "*=",
	TDivEq:       "/=",
	TLshiftEq:    "<<=",
	TLshift:      "<<",
	TRshiftEq:    ">>=",
	TRshift:      ">>",
	TPlusPlus:    "++",
	TPlusEq:      "+=",
	TMinusMinus:  "--",
	TMinusEq:     "-=",
	TOrEq:        "|=",
	TXorEq:       "^=",
	TAndEq:       "&=",
	TLt:          "<",
	TLe:          "<=",
	TGt:          ">",
	TGe:          ">=",
	TEq:          "==",
	TNeq:         "!=",
	TAnd:         "&&",
	TOr:          "||",
	TBitClear:    "&^",
	TSend:        "<-",
}

func (t TokenType) String() string {
	name, ok := tokenTypes[t]
	if ok {
		return name
	}
	if t < 256 {
		return fmt.Sprintf("%c", t)
	}
	return fmt.Sprintf("{TokenType %d}", t)
}

var binaryTypes = map[TokenType]ast.BinaryType{
	'*':       ast.BinaryMul,
	'+':       ast.BinaryAdd,
	'-':       ast.BinarySub,
	'/':       ast.BinaryDiv,
	'%':       ast.BinaryMod,
	TLt:       ast.BinaryLt,
	TLe:       ast.BinaryLe,
	TGt:       ast.BinaryGt,
	TGe:       ast.BinaryGe,
	TEq:       ast.BinaryEq,
	TNeq:      ast.BinaryNeq,
	TAnd:      ast.BinaryAnd,
	TOr:       ast.BinaryOr,
	'&':       ast.BinaryBand,
	'|':       ast.BinaryBor,
	'^':       ast.BinaryBxor,
	TBitClear: ast.BinaryBclear,
	TLshift:   ast.BinaryLshift,
	TRshift:   ast.BinaryRshift,
}

// BinaryType returns token's binary type.
func (t TokenType) BinaryType() ast.BinaryType {
	bt, ok := binaryTypes[t]
	if ok {
		return bt
	}
	panic(fmt.Sprintf("invalid binary operator %s", t))
}

var unaryTypes = map[TokenType]ast.UnaryType{
	'+':   ast.UnaryPlus,
	'-':   ast.UnaryMinus,
	'!':   ast.UnaryNot,
	'^':   ast.UnaryXor,
	'*':   ast.UnaryPtr,
	'&':   ast.UnaryAddr,
	TSend: ast.UnarySend,
}

// UnaryType returns token's unary type.
func (t TokenType) UnaryType() ast.UnaryType {
	ut, ok := unaryTypes[t]
	if ok {
		return ut
	}
	panic(fmt.Sprintf("invalid unary operator %s", t))
}

var symbols = map[string]TokenType{
	"import": TSymImport,
	"const":  TSymConst,
	"type":   TSymType,
	"for":    TSymFor,
	"range":  TSymRange,
	"nil":    TSymNil,
	"else":   TSymElse,
	// "break":    TSymBreak,
	// "continue": TSymContinue,
	// "goto":     TSymGoto,
	"func":    TSymFunc,
	"if":      TSymIf,
	"package": TSymPackage,
	"return":  TSymReturn,
	"struct":  TSymStruct,
	"var":     TSymVar,
}

// Token specifies an input token.
type Token struct {
	Type     TokenType
	From     utils.Point
	To       utils.Point
	StrVal   string
	ConstVal interface{}
	TypeInfo types.Info
}

func (t *Token) String() string {
	var str string
	if len(t.StrVal) > 0 {
		str = t.StrVal
	} else {
		switch val := t.ConstVal.(type) {
		case uint64:
			str = strconv.FormatUint(val, 10)
		case bool:
			str = fmt.Sprintf("%v", val)
		case *mpa.Int:
			str = val.String()
		default:
			str = t.Type.String()
		}
	}
	return str
}

// Lexer implements QCL lexical analyzer.
type Lexer struct {
	in          *bufio.Reader
	point       utils.Point
	tokenStart  utils.Point
	ungot       *Token
	unread      bool
	unreadRune  rune
	unreadSize  int
	unreadPoint utils.Point
	history     map[int][]rune
	lastComment Comment
}

// NewLexer creates a new lexer for the input.
func NewLexer(source string, in io.Reader) *Lexer {
	return &Lexer{
		in: bufio.NewReader(in),
		point: utils.Point{
			Source: source,
			Line:   1,
			Col:    0,
		},
		history: make(map[int][]rune),
	}
}

// Source returns the lexer source name.
func (l *Lexer) Source() string {
	return l.point.Source
}

// ReadRune reads the next input rune.
func (l *Lexer) ReadRune() (rune, int, error) {
	if l.unread {
		l.point, l.unreadPoint = l.unreadPoint, l.point
		l.unread = false
		return l.unreadRune, l.unreadSize, nil
	}
	r, size, err := l.in.ReadRune()
	if err != nil {
		return r, size, err
	}

	l.unreadRune = r
	l.unreadSize = size
	l.unreadPoint = l.point
	if r == '\n' {
		l.point.Line++
		l.point.Col = 0
	} else {
		l.point.Col++
		l.history[l.point.Line] = append(l.history[l.point.Line], r)
	}

	return r, size, nil
}

// UnreadRune unreads the last rune.
func (l *Lexer) UnreadRune() error {
	l.point, l.unreadPoint = l.unreadPoint, l.point
	l.unread = true
	return nil
}

// FlushEOL discards all remaining input from the current source code
// line.
func (l *Lexer) FlushEOL() error {
	for {
		r, _, err := l.ReadRune()
		if err != nil {
			if err != io.EOF {
				return err
			}
			return nil
		}
		if r == '\n' {
			return nil
		}
	}
}

// Get gets the next token.
func (l *Lexer) Get() (*Token, error) {
	if l.ungot != nil {
		token := l.ungot
		l.ungot = nil
		return token, nil
	}

	for {
		l.tokenStart = l.point
		r, _, err := l.ReadRune()
		if err != nil {
			return nil, err
		}
		if unicode.IsSpace(r) {
			continue
		}
		switch r {
		case '%', '(', ')', '{', '}', '[', ']', ',', ';', '.':
			return l.Token(TokenType(r)), nil

		case '^':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token('^'), nil
				}
				return nil, err
			}
			switch r {
			case '=':
				return l.Token(TXorEq), nil
			default:
				l.UnreadRune()
				return l.Token('^'), nil
			}

		case '+':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token('+'), nil
				}
				return nil, err
			}
			switch r {
			case '+':
				return l.Token(TPlusPlus), nil
			case '=':
				return l.Token(TPlusEq), nil
			default:
				l.UnreadRune()
				return l.Token('+'), nil
			}

		case '-':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token('-'), nil
				}
				return nil, err
			}
			switch r {
			case '-':
				return l.Token(TMinusMinus), nil
			case '=':
				return l.Token(TMinusEq), nil
			default:
				l.UnreadRune()
				return l.Token('-'), nil
			}

		case '*':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token('*'), nil
				}
				return nil, err
			}
			switch r {
			case '=':
				return l.Token(TMultEq), nil

			default:
				l.UnreadRune()
				return l.Token('*'), nil
			}

		case '/':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token('/'), nil
				}
				return nil, err
			}
			switch r {
			case '/':
				var comment []rune
				start := l.point
				for {
					r, _, err := l.ReadRune()
					if err != nil {
						return nil, err
					}
					if r == '\n' {
						break
					}
					comment = append(comment, r)
				}
				l.commentLine(string(comment), start)
				continue

			case '*':
				var comment []rune
				start := l.point
				for {
					r, _, err := l.ReadRune()
					if err != nil {
						return nil, err
					}
					if r == '*' {
						r, _, err = l.ReadRune()
						if err != nil {
							return nil, err
						}
						if r == '/' {
							break
						}
						comment = append(comment, '*')
					}
					comment = append(comment, r)
				}
				l.commentLine(string(comment), start)
				continue

			case '=':
				return l.Token(TDivEq), nil

			default:
				l.UnreadRune()
				return l.Token('/'), nil
			}

		case '<':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token(TLt), nil
				}
				return nil, err
			}
			switch r {
			case '=':
				return l.Token(TLe), nil
			case '<':
				r, _, err = l.ReadRune()
				if err != nil {
					if err == io.EOF {
						return l.Token(TLshift), nil
					}
					return nil, err
				}
				if r == '=' {
					return l.Token(TLshiftEq), nil
				}
				l.UnreadRune()
				return l.Token(TLshift), nil
			default:
				l.UnreadRune()
				return l.Token(TLt), nil
			}

		case '>':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token(TGt), nil
				}
				return nil, err
			}
			switch r {
			case '=':
				return l.Token(TGe), nil
			case '>':
				r, _, err = l.ReadRune()
				if err != nil {
					if err == io.EOF {
						return l.Token(TRshift), nil
					}
					return nil, err
				}
				if r == '=' {
					return l.Token(TRshiftEq), nil
				}
				l.UnreadRune()
				return l.Token(TRshift), nil
			default:
				l.UnreadRune()
				return l.Token(TGt), nil
			}

		case '=':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token('='), nil
				}
				return nil, err
			}
			switch r {
			case '=':
				return l.Token(TEq), nil
			default:
				l.UnreadRune()
				return l.Token('='), nil
			}

		case ':':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token(':'), nil
				}
			}
			switch r {
			case '=':
				return l.Token(TDefAssign), nil
			default:
				l.UnreadRune()
				return l.Token(':'), nil
			}

		case '|':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token('|'), nil
				}
				return nil, err
			}
			switch r {
			case '|':
				return l.Token(TOr), nil
			case '=':
				return l.Token(TOrEq), nil
			default:
				l.UnreadRune()
				return l.Token('|'), nil
			}

		case '&':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token('&'), nil
				}
				return nil, err
			}
			switch r {
			case '&':
				return l.Token(TAnd), nil
			case '^':
				return l.Token(TBitClear), nil
			case '=':
				return l.Token(TAndEq), nil
			default:
				l.UnreadRune()
				return l.Token('&'), nil
			}

		case '"':
			var val string
			for {
				r, _, err := l.ReadRune()
				if err != nil {
					return nil, err
				}
				if r == '"' {
					break
				} else if r == '\\' {
					l.UnreadRune()
					r, err = l.readEscape()
					if err != nil {
						return nil, err
					}
				}
				val += string(r)
			}
			token := l.Token(TConstant)
			token.ConstVal = val
			return token, nil

		case '\'':
			i32, err := l.readEscape()
			if err != nil {
				return nil, err
			}
			r, _, err = l.ReadRune()
			if err != nil {
				return nil, err
			}
			if r != '\'' {
				l.UnreadRune()
				return nil, l.errUnexpected(r)
			}
			token := l.Token(TConstant)
			token.ConstVal = int64(i32)
			return token, nil

		case '!':
			r, _, err := l.ReadRune()
			if err != nil {
				if err == io.EOF {
					return l.Token('!'), nil
				}
				return nil, err
			}
			switch r {
			case '=':
				return l.Token(TNeq), nil
			default:
				l.UnreadRune()
				return l.Token('!'), nil
			}

		case '0':
			var ival *mpa.Int

			r, _, err := l.ReadRune()
			if err != nil {
				if err != io.EOF {
					return nil, err
				}
			} else {
				switch r {
				case 'b', 'B':
					ival, err = l.readBinaryLiteral([]rune{'0', r})
				case 'o', 'O':
					ival, err = l.readOctalLiteral([]rune{'0', r})
				case 'x', 'X':
					ival, err = l.readHexLiteral([]rune{'0', r})
				case '0', '1', '2', '3', '4', '5', '6', '7':
					ival, err = l.readOctalLiteral([]rune{'0', r})
				default:
					l.UnreadRune()
				}
				if err != nil {
					return nil, err
				}
			}
			if ival == nil {
				ival = mpa.NewInt(0, 0)
			}
			token := l.Token(TConstant)
			token.ConstVal = ival
			return token, nil

		default:
			if unicode.IsLetter(r) || r == '_' {
				symbol := string(r)
				for {
					r, _, err := l.ReadRune()
					if err != nil {
						if err != io.EOF {
							return nil, err
						}
						break
					}
					if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
						l.UnreadRune()
						break
					}
					symbol += string(r)
				}
				tt, ok := symbols[symbol]
				if ok {
					return l.Token(tt), nil
				}
				if symbol == "true" || symbol == "false" {
					token := l.Token(TConstant)
					token.ConstVal = symbol == "true"
					return token, nil
				}

				token := l.Token(TIdentifier)
				token.StrVal = symbol
				return token, nil
			}
			if unicode.IsDigit(r) {
				val := []rune{r}
				for {
					r, _, err := l.ReadRune()
					if err != nil {
						if err != io.EOF {
							return nil, err
						}
						break
					}
					if unicode.IsDigit(r) {
						val = append(val, r)
					} else {
						l.UnreadRune()
						break
					}
				}
				ival, ok := mpa.Parse(string(val), 10)
				if !ok {
					return nil, fmt.Errorf("invalid literal '%s'", string(val))
				}
				token := l.Token(TConstant)
				token.ConstVal = ival
				return token, nil
			}
			l.UnreadRune()
			return nil, l.errUnexpected(r)
		}
	}
}

func (l *Lexer) readEscape() (int32, error) {
	var i32 int32
	r, _, err := l.ReadRune()
	if err != nil {
		return 0, err
	}
	if r == '\\' {
		r, _, err = l.ReadRune()
		if err != nil {
			return 0, err
		}
		switch r {
		case 'a':
			i32 = '\a'
		case 'b':
			i32 = '\b'
		case 'f':
			i32 = '\f'
		case 'n':
			i32 = '\n'
		case 'r':
			i32 = '\r'
		case 't':
			i32 = '\t'
		case 'v':
			i32 = '\v'
		case '\\':
			i32 = '\\'
		case 'u':
			for i := 0; i < 4; i++ {
				i32 <<= 4
				r, _, err = l.ReadRune()
				if err != nil {
					return 0, err
				}
				if '0' <= r && r <= '9' {
					i32 += r - '0'
				} else if 'a' <= r && r <= 'f' {
					i32 += 10 + r - 'a'
				} else if 'A' <= r && r <= 'F' {
					i32 += 10 + r - 'A'
				} else {
					l.UnreadRune()
					return 0, l.errUnexpected(r)
				}
			}
		case 'x':
			for i := 0; i < 2; i++ {
				i32 <<= 4
				r, _, err = l.ReadRune()
				if err != nil {
					return 0, err
				}
				if '0' <= r && r <= '9' {
					i32 += r - '0'
				} else if 'a' <= r && r <= 'f' {
					i32 += 10 + r - 'a'
				} else if 'A' <= r && r <= 'F' {
					i32 += 10 + r - 'A'
				} else {
					l.UnreadRune()
					return 0, l.errUnexpected(r)
				}
			}
		default:
			if '0' <= r && r <= '7' {
				i32 = r - '0'
				for i := 0; i < 2; i++ {
					r, _, err = l.ReadRune()
					if err != nil {
						return 0, err
					}
					if r < '0' || r > '7' {
						l.UnreadRune()
						return 0, l.errUnexpected(r)
					}
					i32 *= 8
					i32 += r - '0'
				}
			} else {
				l.UnreadRune()
				return 0, l.errUnexpected(r)
			}
		}
	} else {
		i32 = int32(r)
	}
	return i32, nil
}

func (l *Lexer) readBinaryLiteral(val []rune) (*mpa.Int, error) {
loop:
	for {
		r, _, err := l.ReadRune()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
		switch r {
		case '0', '1':
			val = append(val, r)
		default:
			l.UnreadRune()
			break loop
		}
	}
	ival, ok := mpa.Parse(string(val), 0)
	if !ok {
		return nil, fmt.Errorf("malformed binary literal '%s'", string(val))
	}
	return ival, nil
}

func (l *Lexer) readOctalLiteral(val []rune) (*mpa.Int, error) {
loop:
	for {
		r, _, err := l.ReadRune()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
		switch r {
		case '0', '1', '2', '3', '4', '5', '6', '7':
			val = append(val, r)
		default:
			l.UnreadRune()
			break loop
		}
	}
	ival, ok := mpa.Parse(string(val), 0)
	if !ok {
		return nil, fmt.Errorf("malformed octal literal '%s'", string(val))
	}
	return ival, nil
}

func (l *Lexer) readHexLiteral(val []rune) (*mpa.Int, error) {
	for {
		r, _, err := l.ReadRune()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
		if unicode.Is(unicode.Hex_Digit, r) {
			val = append(val, r)
		} else {
			l.UnreadRune()
			break
		}
	}
	ival, ok := mpa.Parse(string(val[2:]), 16)
	if !ok {
		return nil, fmt.Errorf("malformed hex literal '%s'", string(val))
	}
	return ival, nil
}

// Unget pushes the token back to the lexer input stream. The next
// call to Get will return it.
func (l *Lexer) Unget(t *Token) {
	l.ungot = t
}

// Token returns a new token for the argument token type.
func (l *Lexer) Token(t TokenType) *Token {
	return &Token{
		Type: t,
		From: l.tokenStart,
		To:   l.point,
	}
}

// Comment describes a comment.
type Comment struct {
	Start utils.Point
	End   utils.Point
	Lines []string
}

// Empty tests if the comment is empty.
func (c Comment) Empty() bool {
	return len(c.Lines) == 0
}

func (l *Lexer) commentLine(line string, loc utils.Point) {
	if l.lastComment.Empty() || l.lastComment.End.Line+1 != loc.Line {
		l.lastComment = Comment{
			Start: loc,
			End:   loc,
			Lines: []string{line},
		}
	} else {
		l.lastComment.End = loc
		l.lastComment.Lines = append(l.lastComment.Lines, line)
	}
}

// Annotations returns the annotations immediately preceding the
// current lexer location.
func (l *Lexer) Annotations(loc utils.Point) ast.Annotations {
	if l.lastComment.Empty() || l.lastComment.End.Line+1 != loc.Line {
		return nil
	}
	return l.lastComment.Lines
}

func (l *Lexer) errUnexpected(r rune) error {
	return fmt.Errorf("%s: unexpected character '%s'", l.point, string(r))
}
