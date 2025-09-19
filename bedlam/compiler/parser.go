//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package compiler

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/ast"
	"source.quilibrium.com/quilibrium/monorepo/bedlam/compiler/utils"
)

// Parser implements QCL parser.
type Parser struct {
	compiler *Compiler
	logger   *utils.Logger
	lexer    *Lexer
	pkg      *ast.Package
}

// NewParser creates a new parser.
func NewParser(source string, compiler *Compiler, logger *utils.Logger,
	in io.Reader) *Parser {
	return &Parser{
		compiler: compiler,
		logger:   logger,
		lexer:    NewLexer(source, in),
	}
}

// Parse parses a package.
func (p *Parser) Parse(pkg *ast.Package) (*ast.Package, error) {
	name, doc, err := p.parsePackage()
	if err != nil {
		return nil, err
	}
	if pkg == nil {
		p.pkg = ast.NewPackage(name, p.lexer.Source(), doc)
	} else {
		// This source file must be in the same package.
		if name != pkg.Name {
			return nil, fmt.Errorf("found packages %s and %s", name, pkg.Name)
		}
		p.pkg = pkg
	}

	token, err := p.lexer.Get()
	if err != nil {
		if err != io.EOF {
			return nil, err
		}
		return p.pkg, nil
	}
	if token.Type == TSymImport {
		_, err = p.needToken('(')
		if err != nil {
			return nil, err
		}
		for {
			t, err := p.lexer.Get()
			if err != nil {
				return nil, err
			}
			if t.Type == ')' {
				break
			}

			var alias string
			if t.Type == TIdentifier {
				alias = t.StrVal
				t, err = p.lexer.Get()
				if err != nil {
					return nil, err
				}
			}
			if t.Type != TConstant {
				return nil, p.errUnexpected(t, TConstant)
			}
			str, ok := t.ConstVal.(string)
			if !ok {
				return nil, p.errUnexpected(t, TConstant)
			}
			_, ok = p.pkg.Imports[str]
			if ok {
				return nil, p.errf(t.From,
					"package %s imported more than once", str)
			}

			if len(alias) == 0 {
				parts := strings.Split(str, "/")
				alias = parts[len(parts)-1]
			}

			p.pkg.Imports[alias] = str
		}
	} else {
		p.lexer.Unget(token)
	}

	for {
		err = p.parseToplevel()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
	}

	return p.pkg, nil
}

var leaves = map[string]bool{
	"errorLoc":      true,
	"errf":          true,
	"errUnexpected": true,
	"needToken":     true,
}

func (p *Parser) errorLoc(msg string) {
	if !p.compiler.params.QCLCErrorLoc {
		return
	}
	for i := 3; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			return
		}
		f := runtime.FuncForPC(pc)
		if f != nil {
			name := f.Name()
			idx := strings.LastIndexByte(name, '.')
			if idx >= 0 {
				name = name[idx+1:]
			}
			if leaves[name] {
				continue
			}
		}
		fmt.Printf("%s:%d: MCPLC error:\n\u2514\u2574%s\n", file, line, msg)
		return
	}
}

func (p *Parser) errf(loc utils.Point, format string, a ...interface{}) error {
	msg := fmt.Sprintf(format, a...)

	p.errorLoc(msg)

	p.lexer.FlushEOL()

	line, ok := p.lexer.history[loc.Line]
	if ok {
		var indicator []rune
		for i := 0; i < loc.Col; i++ {
			var r rune
			if line[i] == '\t' {
				r = '\t'
			} else {
				r = ' '
			}
			indicator = append(indicator, r)
		}
		indicator = append(indicator, '^')
		pos := fmt.Sprintf("%s\n%s", string(line), string(indicator))
		compilerError := &CompileError{
			Stage:     CompileStageParse,
			SourcePos: pos,
			Location:  &loc,
			Err:       errors.New(msg),
		}
		p.logger.Errorf(loc, "%s\n%s\n%s\n",
			msg, string(line), string(indicator))

		return compilerError
	}
	p.logger.Errorf(loc, "%s", msg)
	compilerError := &CompileError{
		Stage:     CompileStageParse,
		SourcePos: fmt.Sprintf("%s:%d:%d", p.lexer.Source(), loc.Line, loc.Col),
		Location:  &loc,
		Err:       errors.New(msg),
	}
	return compilerError
}

func (p *Parser) errUnexpected(offending *Token, expected TokenType) error {
	return p.errf(offending.From, "unexpected token '%s': expected '%s'",
		offending, expected)
}

func (p *Parser) needToken(tt TokenType) (*Token, error) {
	token, err := p.lexer.Get()
	if err != nil {
		return nil, err
	}
	if token.Type != tt {
		p.lexer.Unget(token)
		return nil, p.errUnexpected(token, tt)
	}
	return token, nil
}

func (p *Parser) sameLine(current utils.Point) bool {
	t, err := p.lexer.Get()
	if err != nil {
		return false
	}
	p.lexer.Unget(t)
	return t.From.Line == current.Line
}

func (p *Parser) parsePackage() (string, ast.Annotations, error) {
	t, err := p.needToken(TSymPackage)
	if err != nil {
		return "", nil, err
	}
	t, err = p.needToken(TIdentifier)
	if err != nil {
		return "", nil, err
	}
	parts := strings.Split(t.StrVal, "/")
	return parts[len(parts)-1], p.lexer.Annotations(t.From), nil
}

func (p *Parser) parseToplevel() error {
	token, err := p.lexer.Get()
	if err != nil {
		return err
	}
	switch token.Type {
	case TSymConst:
		// XXX not fully according to syntax:
		//
		// ConstDecl = 'const', ( ConstSpec | '(', { ConstSpec }, ')' );
		// ConstSpec = IdentifierList, [ Type ], '=', ExpressionList;
		// ExpressionList = Expression, { ',', Expression };
		return p.parseGlobalVar(true, p.lexer.Annotations(token.From))

	case TSymVar:
		// XXX not fully according to syntax:
		//
		// VarDecl = 'var', ( VarSpec | '(', { VarSpec }, ')' );
		// VarSpec = IdentifierList, (   Type, [ '=', ExpressionList ]
		//                             |         '=', ExpressionList   );
		return p.parseGlobalVar(false, p.lexer.Annotations(token.From))

	case TSymType:
		return p.parseTypeDecl(p.lexer.Annotations(token.From))

	case TSymFunc:
		// FunctionDecl | MethodDecl
		//
		// FunctionDecl = "func" FunctionName Signature [ FunctionBody ] .
		// FunctionName = identifier .
		// FunctionBody = Block .
		//
		// MethodDecl = "func" Receiver MethodName Signature [ FunctionBody ] .
		// MethodName = identifier .
		// Receiver   = Parameters .
		n, err := p.lexer.Get()
		if err != nil {
			return err
		}
		p.lexer.Unget(n)
		switch n.Type {
		case TIdentifier:
			f, err := p.parseFunc(p.lexer.Annotations(token.From))
			if err != nil {
				return err
			}
			_, ok := p.pkg.Functions[f.Name]
			if ok {
				return p.errf(f.Location(), "function %s already defined",
					f.Name)
			}
			p.pkg.Functions[f.Name] = f

		case '(':
			loc := n.From
			_, err = p.needToken('(')
			if err != nil {
				return err
			}
			n, err := p.lexer.Get()
			if err != nil {
				return err
			}
			if n.Type != TIdentifier {
				return p.errUnexpected(n, TIdentifier)
			}
			ti, err := p.parseType()
			if err != nil {
				return err
			}
			_, err = p.needToken(')')
			if err != nil {
				return err
			}
			f, err := p.parseFunc(p.lexer.Annotations(token.From))
			if err != nil {
				return err
			}
			f.This = &ast.Variable{
				Point: loc,
				Name:  n.StrVal,
				Type:  ti,
			}
			return p.addMethod(ti, f)

		default:
			return p.errf(n.From, "unexpected '%s', expecting name or (", n)
		}

	default:
		return p.errf(token.From, "unexpected token '%s'", token.Type)
	}

	return nil
}

func (p *Parser) addMethod(ti *ast.TypeInfo, f *ast.Func) error {
	t := ti
	if t.Type == ast.TypePointer {
		t = t.ElementType
	}
	if t.Type != ast.TypeName {
		return p.errf(ti.Point,
			"invalid receiver type %s (%s is not a defined type)", ti, ti)
	}

	for _, pkgType := range p.pkg.Types {
		if pkgType.TypeName == t.Name.Name {
			if pkgType.Methods == nil {
				pkgType.Methods = make(map[string]*ast.Func)
			}
			_, ok := pkgType.Methods[f.Name]
			if ok {
				return p.errf(f.Point, "(%s).%s redeclared in this block",
					ti, f.Name)
			}
			pkgType.Methods[f.Name] = f
			return nil
		}
	}

	return p.errf(ti.Location(), "type %s.%s not found", p.pkg.Name, t.Name)
}

func (p *Parser) parseGlobalVar(isConst bool,
	annotations ast.Annotations) error {

	token, err := p.lexer.Get()
	if err != nil {
		return err
	}
	switch token.Type {
	case TIdentifier:
		return p.parseGlobalVarDef(token, isConst, annotations)

	case '(':
		for {
			t, err := p.lexer.Get()
			if err != nil {
				return err
			}
			if t.Type == ')' {
				return nil
			}
			err = p.parseGlobalVarDef(t, isConst,
				p.lexer.Annotations(t.From))
			if err != nil {
				return err
			}
		}

	default:
		return p.errf(token.From, "unexpected token '%s'", token.Type)
	}
}

func (p *Parser) parseGlobalVarDef(token *Token, isConst bool,
	annotations ast.Annotations) error {

	if token.Type != TIdentifier {
		return p.errf(token.From, "unexpected token '%s'", token.Type)
	}

	t, err := p.lexer.Get()
	if err != nil {
		return err
	}
	var varType *ast.TypeInfo
	var init ast.AST

	if t.Type == '=' {
		init, err = p.parseExpr(false)
		if err != nil {
			return err
		}
	} else {
		p.lexer.Unget(t)
		varType, err = p.parseType()
		if err != nil {
			return err
		}
		t, err = p.lexer.Get()
		if err != nil {
			return nil
		}
		if t.Type == '=' {
			init, err = p.parseExpr(false)
			if err != nil {
				return err
			}
		} else {
			p.lexer.Unget(t)
		}
	}

	if isConst {
		p.pkg.Constants = append(p.pkg.Constants, &ast.ConstantDef{
			Point:       token.From,
			Name:        token.StrVal,
			Type:        varType,
			Init:        init,
			Annotations: annotations,
		})
	} else {
		p.pkg.Variables = append(p.pkg.Variables, &ast.VariableDef{
			Point:       token.From,
			Names:       []string{token.StrVal},
			Type:        varType,
			Init:        init,
			Annotations: annotations,
		})
	}

	return nil
}

func (p *Parser) parseTypeDecl(annotations ast.Annotations) error {
	name, err := p.needToken(TIdentifier)
	if err != nil {
		return err
	}
	t, err := p.lexer.Get()
	if err != nil {
		return err
	}
	switch t.Type {
	case TSymStruct:
		loc := t.From
		_, err := p.needToken('{')
		if err != nil {
		}
		var fields []ast.StructField
		for {
			t, err := p.lexer.Get()
			if err != nil {
				return err
			}
			if t.Type == '}' {
				break
			}
			var names []*Token
			for {
				if t.Type != TIdentifier {
					return p.errf(t.From, "unexpected token '%s'", t.Type)
				}
				names = append(names, t)
				t, err = p.lexer.Get()
				if err != nil {
					return err
				}
				if t.Type != ',' {
					p.lexer.Unget(t)
					break
				}
				t, err = p.lexer.Get()
				if err != nil {
					return err
				}
			}

			typeInfo, err := p.parseType()
			if err != nil {
				return err
			}
			// Expand names.
			for _, n := range names {
				fields = append(fields, ast.StructField{
					Point: n.From,
					Name:  n.StrVal,
					Type:  typeInfo,
				})
			}
		}
		typeInfo := &ast.TypeInfo{
			Point:        loc,
			Type:         ast.TypeStruct,
			TypeName:     name.StrVal,
			StructFields: fields,
			Annotations:  annotations,
		}
		p.pkg.Types = append(p.pkg.Types, typeInfo)
		return nil

	case '=':
		ti, err := p.parseType()
		if err != nil {
			return err
		}
		typeInfo := &ast.TypeInfo{
			Point:       ti.Point,
			Type:        ast.TypeAlias,
			TypeName:    name.StrVal,
			AliasType:   ti,
			Annotations: annotations,
		}
		p.pkg.Types = append(p.pkg.Types, typeInfo)
		return nil

	default:
		// TypeDef = identifier Type .
		p.lexer.Unget(t)
		typeInfo, err := p.parseType()
		if err != nil {
			return err
		}
		typeInfo.TypeName = name.StrVal
		typeInfo.Annotations = annotations
		p.pkg.Types = append(p.pkg.Types, typeInfo)
		return nil
	}
}

func (p *Parser) parseFunc(annotations ast.Annotations) (*ast.Func, error) {
	name, err := p.needToken(TIdentifier)
	if err != nil {
		return nil, err
	}

	_, err = p.needToken('(')
	if err != nil {
		return nil, err
	}

	// Argument list.

	var arguments []*ast.Variable

	t, err := p.lexer.Get()
	if err != nil {
		return nil, err
	}
	if t.Type != ')' {
		p.lexer.Unget(t)
		for {
			t, err = p.needToken(TIdentifier)
			if err != nil {
				return nil, err
			}
			arg := &ast.Variable{
				Point: t.From,
				Name:  t.StrVal,
			}

			t, err = p.lexer.Get()
			if err != nil {
				return nil, err
			}
			if t.Type == ',' {
				arguments = append(arguments, arg)
				continue
			}
			p.lexer.Unget(t)

			// Type.
			typeInfo, err := p.parseType()
			if err != nil {
				return nil, err
			}
			arg.Type = typeInfo

			// All untyped arguments get this type.
			for i := len(arguments) - 1; i >= 0; i-- {
				if arguments[i].Type != nil {
					break
				}
				arguments[i].Type = typeInfo
			}

			// Append new argument.
			arguments = append(arguments, arg)

			t, err = p.lexer.Get()
			if err != nil {
				return nil, err
			}
			if t.Type == ')' {
				break
			}
			if t.Type != ',' {
				return nil, p.errUnexpected(t, ',')
			}
		}
	}

	// Return values.
	var returnValues []*ast.Variable
	var namedReturnValues bool

	n, err := p.lexer.Get()
	if err != nil {
		return nil, err
	}
	switch n.Type {
	case '(':
		var identifiers []*ast.TypeInfo

		for {
			typeInfo, err := p.parseType()
			if err != nil {
				return nil, err
			}
			// Peek next token.
			n, err = p.lexer.Get()
			if err != nil {
				return nil, err
			}
			p.lexer.Unget(n)

			switch n.Type {
			case ',':
				identifiers = append(identifiers, typeInfo)

			case ')':
				if namedReturnValues {
					return nil, p.errf(typeInfo.Point,
						"mixing named and unnamed return values")
				}
				identifiers = append(identifiers, typeInfo)
				for _, id := range identifiers {
					returnValues = append(returnValues, &ast.Variable{
						Point: id.Point,
						Type:  id,
					})
				}

			default:
				// typeInfo is named return variable and the next
				// component is its type.
				if !typeInfo.IsIdentifier() {
					return nil, p.errf(n.From,
						"unexpected %s, expecting comma or )", n)
				}
				identifiers = append(identifiers, typeInfo)

				typeInfo, err = p.parseType()
				if err != nil {
					return nil, err
				}
				// Add current list of identifiers to return
				// values. All elements in identifiers must be
				// identifiers.
				for _, id := range identifiers {
					if !id.IsIdentifier() {
						return nil, p.errf(id.Point,
							"mixing named and unnamed return values")
					}
					returnValues = append(returnValues, &ast.Variable{
						Point: id.Point,
						Name:  id.String(),
						Type:  typeInfo,
					})
				}
				namedReturnValues = true
				identifiers = nil
			}
			n, err = p.lexer.Get()
			if err != nil {
				return nil, err
			}
			if n.Type == ')' {
				break
			}
			if n.Type != ',' {
				return nil, p.errUnexpected(n, ',')
			}
		}
		_, err = p.needToken('{')
		if err != nil {
			return nil, err
		}

	case '{':

	default:
		p.lexer.Unget(n)
		typeInfo, err := p.parseType()
		if err != nil {
			return nil, err
		}
		returnValues = append(returnValues, &ast.Variable{
			Point: n.From,
			Type:  typeInfo,
		})
		_, err = p.needToken('{')
		if err != nil {
			return nil, err
		}
	}

	body, end, err := p.parseBlock()
	if err != nil {
		return nil, err
	}

	return ast.NewFunc(name.From, name.StrVal, arguments, returnValues,
		namedReturnValues, body, end, annotations), nil
}

func (p *Parser) parseBlock() (ast.List, utils.Point, error) {
	var result ast.List
	var end utils.Point
	for {
		t, err := p.lexer.Get()
		if err != nil {
			return nil, utils.Point{}, err
		}
		if t.Type == '}' {
			end = t.From
			break
		}
		p.lexer.Unget(t)

		ast, err := p.parseStatement(false)
		if err != nil {
			return nil, utils.Point{}, err
		}
		result = append(result, ast)
	}
	return result, end, nil
}

func (p *Parser) parseStatement(needLBrace bool) (ast.AST, error) {
	tStmt, err := p.lexer.Get()
	if err != nil {
		return nil, err
	}
	switch tStmt.Type {
	case TSymVar:
		var names []string
		for {
			tName, err := p.needToken(TIdentifier)
			if err != nil {
				return nil, err
			}
			names = append(names, tName.StrVal)
			t, err := p.lexer.Get()
			if err != nil {
				return nil, err
			}
			if t.Type != ',' {
				p.lexer.Unget(t)
				break
			}
		}
		typeInfo, err := p.parseType()
		if err != nil {
			return nil, err
		}

		t, err := p.lexer.Get()
		if err != nil {
			return nil, err
		}
		var expr ast.AST
		if t.Type == '=' {
			// Initializer.
			expr, err = p.parseExpr(needLBrace)
			if err != nil {
				return nil, err
			}
		} else {
			p.lexer.Unget(t)
		}

		return &ast.VariableDef{
			Point: tStmt.From,
			Names: names,
			Type:  typeInfo,
			Init:  expr,
		}, nil

	case TSymIf:
		expr, err := p.parseExpr(true)
		if err != nil {
			return nil, err
		}
		_, err = p.needToken('{')
		if err != nil {
			return nil, err
		}

		var b1, b2 ast.AST
		b1, _, err = p.parseBlock()
		if err != nil {
			return nil, err
		}
		t, err := p.lexer.Get()
		if err != nil {
			return nil, err
		}
		if t.Type == TSymElse {
			n, err := p.lexer.Get()
			if err != nil {
				return nil, err
			}
			switch n.Type {
			case '{':
				b2, _, err = p.parseBlock()
				if err != nil {
					return nil, err
				}

			case TSymIf:
				p.lexer.Unget(n)
				b2, err = p.parseStatement(needLBrace)
				if err != nil {
				}

			default:
				return nil, p.errf(n.From, "unexpected %s, expected if or {", n)
			}
		} else {
			p.lexer.Unget(t)
		}
		return &ast.If{
			Expr:  expr,
			True:  b1,
			False: b2,
		}, nil

	case TSymReturn:
		var exprs []ast.AST
		if p.sameLine(tStmt.To) {
			expr, err := p.parseExpr(needLBrace)
			if err != nil {
				return nil, err
			}
			exprs = append(exprs, expr)
			for {
				t, err := p.lexer.Get()
				if err != nil {
					return nil, err
				}
				if t.Type != ',' {
					p.lexer.Unget(t)
					break
				}
				expr, err = p.parseExpr(needLBrace)
				if err != nil {
					return nil, err
				}
				exprs = append(exprs, expr)
			}
		}
		return &ast.Return{
			Point: tStmt.From,
			Exprs: exprs,
		}, nil

		// ForStmt = "for" [ Condition | ForClause | RangeClause ] Block .
		// Condition = Expression .
	case TSymFor:
		var init ast.AST
		n, err := p.lexer.Get()
		if err != nil {
			return nil, err
		}
		p.lexer.Unget(n)
		if n.Type != ';' {
			// init | Condition | RangeClause
			init, err = p.parseStatement(true)
			if err != nil {
				return nil, err
			}
			forRange, ok := init.(*ast.ForRange)
			if ok {
				// for RangeClause
				_, err := p.needToken('{')
				if err != nil {
					return nil, err
				}
				body, _, err := p.parseBlock()
				if err != nil {
					return nil, err
				}
				forRange.Body = body
				return forRange, nil
			}
			// init | Condition
			n, err := p.lexer.Get()
			if err != nil {
				return nil, err
			}
			if n.Type == '{' {
				// for Condition
				list, ok := init.(ast.List)
				if !ok || len(list) != 1 {
					return nil, p.errf(init.Location(),
						"unexpected condition: %v", init)
				}

				body, _, err := p.parseBlock()
				if err != nil {
					return nil, err
				}
				return &ast.For{
					Point: tStmt.From,
					Cond:  list[0],
					Body:  body,
				}, nil
			}
			p.lexer.Unget(n)
		}
		_, err = p.needToken(';')
		if err != nil {
			return nil, err
		}
		cond, err := p.parseExpr(false)
		if err != nil {
			return nil, err
		}
		_, err = p.needToken(';')
		if err != nil {
			return nil, err
		}
		inc, err := p.parseStatement(true)
		if err != nil {
			return nil, err
		}
		_, err = p.needToken('{')
		if err != nil {
			return nil, err
		}
		body, _, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		return &ast.For{
			Point: tStmt.From,
			Init:  init,
			Cond:  cond,
			Inc:   inc,
			Body:  body,
		}, nil

	default:
		p.lexer.Unget(tStmt)
		lvalues, err := p.parseExprList(needLBrace)
		if err != nil {
			return nil, err
		}
		t, err := p.lexer.Get()
		if err != nil {
			return nil, err
		}
		switch t.Type {
		case '=', TDefAssign:
			n, err := p.lexer.Get()
			if err != nil {
				return nil, err
			}
			if n.Type == TSymRange {
				expr, err := p.parseExpr(true)
				if err != nil {
					return nil, err
				}
				return &ast.ForRange{
					Point:    t.From,
					ExprList: lvalues,
					Def:      t.Type == TDefAssign,
					Expr:     expr,
				}, nil
			}

			p.lexer.Unget(n)

			values, err := p.parseExprList(needLBrace)
			if err != nil {
				return nil, err
			}
			return &ast.Assign{
				Point:   t.From,
				LValues: lvalues,
				Exprs:   values,
				Define:  t.Type == TDefAssign,
			}, nil

		case TPlusEq, TMinusEq, TMultEq, TDivEq, TOrEq, TXorEq, TAndEq,
			TLshiftEq, TRshiftEq:
			if len(lvalues) != 1 {
				return nil, p.errf(tStmt.From, "expected 1 expression")
			}
			var op ast.BinaryType
			switch t.Type {
			case TPlusEq:
				op = ast.BinaryAdd
			case TMinusEq:
				op = ast.BinarySub
			case TMultEq:
				op = ast.BinaryMul
			case TDivEq:
				op = ast.BinaryDiv
			case TOrEq:
				op = ast.BinaryBor
			case TXorEq:
				op = ast.BinaryBxor
			case TAndEq:
				op = ast.BinaryBand
			case TLshiftEq:
				op = ast.BinaryLshift
			case TRshiftEq:
				op = ast.BinaryRshift
			default:
				panic(t.Type)
			}
			value, err := p.parseExpr(needLBrace)
			if err != nil {
				return nil, err
			}
			return &ast.Assign{
				Point:   t.From,
				LValues: lvalues,
				Exprs: []ast.AST{
					&ast.Binary{
						Point: t.From,
						Left:  lvalues[0],
						Op:    op,
						Right: value,
					},
				},
			}, nil

		case TPlusPlus, TMinusMinus:
			if len(lvalues) != 1 {
				return nil, p.errf(tStmt.From, "expected 1 expression")
			}

			var op ast.BinaryType
			if t.Type == TPlusPlus {
				op = ast.BinaryAdd
			} else {
				op = ast.BinarySub
			}
			return &ast.Assign{
				Point:   t.From,
				LValues: lvalues,
				Exprs: []ast.AST{
					&ast.Binary{
						Point: t.From,
						Left:  lvalues[0],
						Op:    op,
						Right: &ast.BasicLit{
							Point: t.From,
							Value: int64(1),
						},
					},
				},
			}, nil

		default:
			p.lexer.Unget(t)
			return ast.List(lvalues), nil
		}
	}
}

func (p *Parser) parseExprList(needLBrace bool) ([]ast.AST, error) {
	var list []ast.AST

	for {
		expr, err := p.parseExpr(needLBrace)
		if err != nil {
			return nil, err
		}
		list = append(list, expr)
		t, err := p.lexer.Get()
		if err != nil {
			return nil, err
		}
		if t.Type != ',' {
			p.lexer.Unget(t)
			break
		}
	}

	return list, nil
}

func (p *Parser) parseExpr(needLBrace bool) (ast.AST, error) {
	// Precedence Operator
	// -----------------------------
	//   5          * / % << >> & &^
	//   4          + - | ^
	//   3          == != < <= > >=
	//   2          &&
	//   1          ||
	return p.parseExprLogicalOr(needLBrace)
}

func (p *Parser) parseExprLogicalOr(needLBrace bool) (ast.AST, error) {
	left, err := p.parseExprLogicalAnd(needLBrace)
	if err != nil {
		return nil, err
	}
	for {
		t, err := p.lexer.Get()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			return left, nil
		}
		if t.Type != TOr {
			p.lexer.Unget(t)
			return left, nil
		}
		right, err := p.parseExprLogicalAnd(needLBrace)
		if err != nil {
			return nil, err
		}
		left = &ast.Binary{
			Point: t.From,
			Left:  left,
			Op:    t.Type.BinaryType(),
			Right: right,
		}
	}
}

func (p *Parser) parseExprLogicalAnd(needLBrace bool) (ast.AST, error) {
	left, err := p.parseExprComparative(needLBrace)
	if err != nil {
		return nil, err
	}
	for {
		t, err := p.lexer.Get()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			return left, nil
		}
		if t.Type != TAnd {
			p.lexer.Unget(t)
			return left, nil
		}
		right, err := p.parseExprComparative(needLBrace)
		if err != nil {
			return nil, err
		}
		left = &ast.Binary{
			Point: t.From,
			Left:  left,
			Op:    t.Type.BinaryType(),
			Right: right,
		}
	}
}

func (p *Parser) parseExprComparative(needLBrace bool) (ast.AST, error) {
	left, err := p.parseExprAdditive(needLBrace)
	if err != nil {
		return nil, err
	}
	for {
		t, err := p.lexer.Get()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			return left, nil
		}
		switch t.Type {
		case TEq, TNeq, TLt, TLe, TGt, TGe:
			right, err := p.parseExprAdditive(needLBrace)
			if err != nil {
				return nil, err
			}
			left = &ast.Binary{
				Point: t.From,
				Left:  left,
				Op:    t.Type.BinaryType(),
				Right: right,
			}

		default:
			p.lexer.Unget(t)
			return left, nil
		}
	}
}

func (p *Parser) parseExprAdditive(needLBrace bool) (ast.AST, error) {
	left, err := p.parseExprMultiplicative(needLBrace)
	if err != nil {
		return nil, err
	}
	for {
		t, err := p.lexer.Get()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			return left, nil
		}
		switch t.Type {
		case '+', '-', '|', '^':
			right, err := p.parseExprMultiplicative(needLBrace)
			if err != nil {
				return nil, err
			}
			left = &ast.Binary{
				Point: t.From,
				Left:  left,
				Op:    t.Type.BinaryType(),
				Right: right,
			}

		default:
			p.lexer.Unget(t)
			return left, nil
		}
	}
}

func (p *Parser) parseExprMultiplicative(needLBrace bool) (ast.AST, error) {
	left, err := p.parseExprUnary(needLBrace)
	if err != nil {
		return nil, err
	}
	for {
		t, err := p.lexer.Get()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			return left, nil
		}
		switch t.Type {
		case '*', '/', '%', TLshift, TRshift, '&', TBitClear:
			right, err := p.parseExprUnary(needLBrace)
			if err != nil {
				return nil, err
			}
			left = &ast.Binary{
				Point: t.From,
				Left:  left,
				Op:    t.Type.BinaryType(),
				Right: right,
			}

		default:
			p.lexer.Unget(t)
			return left, nil
		}
	}
}

// UnaryExpr  = PrimaryExpr | unary_op UnaryExpr .
func (p *Parser) parseExprUnary(needLBrace bool) (ast.AST, error) {
	t, err := p.lexer.Get()
	if err != nil {
		return nil, err
	}
	switch t.Type {
	case '+', '-', '!', '^', '*', '&', TSend:
		expr, err := p.parseExprUnary(needLBrace)
		if err != nil {
			return nil, err
		}
		return &ast.Unary{
			Point: t.From,
			Type:  t.Type.UnaryType(),
			Expr:  expr,
		}, nil

	default:
		p.lexer.Unget(t)
		return p.parseExprPrimary(needLBrace)
	}
}

// PrimaryExpr =
//     Operand |
//     Conversion |
//     MethodExpr |
//     PrimaryExpr Selector |
//     PrimaryExpr Index |
//     PrimaryExpr Slice |
//     PrimaryExpr TypeAssertion |
//     PrimaryExpr Arguments .
//
// Selector       = "." identifier .
// Index          = "[" Expression "]" .
// Slice          = "[" [ Expression ] ":" [ Expression ] "]" |
//                  "[" [ Expression ] ":" Expression ":" Expression "]" .
// TypeAssertion  = "." "(" Type ")" .
// Arguments      = "(" [ ( ExpressionList | Type [ "," ExpressionList ] ) [ "..." ] [ "," ] ] ")" .

func (p *Parser) parseExprPrimary(needLBrace bool) (ast.AST, error) {
	primary, err := p.parseOperand(needLBrace)
	if err != nil {
		return nil, err
	}

primary:
	for {
		t, err := p.lexer.Get()
		if err != nil {
			if err == io.EOF {
				return primary, nil
			}
			return nil, err
		}
		switch t.Type {
		case '.':
			// Selector.
			return nil, p.errf(t.From, "selector not implemented yet")

		case '[':
			var expr1, expr2 ast.AST

			n, err := p.lexer.Get()
			if err != nil {
				return nil, err
			}
			if n.Type != ':' {
				p.lexer.Unget(n)
				expr1, err = p.parseExpr(needLBrace)
				if err != nil {
					return nil, err
				}
				n, err = p.lexer.Get()
				if err != nil {
					return nil, err
				}
				if n.Type == ']' {
					primary = &ast.Index{
						Point: primary.Location(),
						Expr:  primary,
						Index: expr1,
					}
					continue primary
				}
				if n.Type != ':' {
					p.lexer.Unget(n)
					return nil, p.errUnexpected(n, ':')
				}
			}
			n, err = p.lexer.Get()
			if err != nil {
				return nil, err
			}
			if n.Type != ']' {
				p.lexer.Unget(n)
				expr2, err = p.parseExpr(needLBrace)
				if err != nil {
					return nil, err
				}
				_, err = p.needToken(']')
				if err != nil {
					return nil, err
				}
			}
			primary = &ast.Slice{
				Point: primary.Location(),
				Expr:  primary,
				From:  expr1,
				To:    expr2,
			}

		case '(':
			vr, ok := primary.(*ast.VariableRef)
			if !ok {
				return nil, p.errf(primary.Location(),
					"non-function %s used as function", primary)
			}
			var arguments []ast.AST
			var isMake bool
			var ti *ast.TypeInfo

			if vr.String() == "make" {
				isMake = true
			}
			n, err := p.lexer.Get()
			if err != nil {
				return nil, err
			}
			if n.Type != ')' {
				p.lexer.Unget(n)
				for {
					if isMake && ti == nil {
						ti, err = p.parseType()
						if err != nil {
							return nil, err
						}
					} else {
						expr, err := p.parseExpr(needLBrace)
						if err != nil {
							return nil, err
						}
						arguments = append(arguments, expr)
					}

					n, err := p.lexer.Get()
					if err != nil {
						return nil, err
					}
					if n.Type == ')' {
						break
					} else if n.Type != ',' {
						return nil, p.errf(n.From, "unexpected token %s", n)
					}
				}
			}
			if isMake {
				if ti == nil {
					return nil, p.errf(primary.Location(),
						"missing arguments to make")
				}
				primary = &ast.Make{
					Point: primary.Location(),
					Type:  ti,
					Exprs: arguments,
				}
			} else if vr.String() == "copy" {
				if len(arguments) != 2 {
					return nil, p.errf(primary.Location(),
						"invalid arguments for copy (expected 2, found %v)",
						len(arguments))
				}
				primary = &ast.Copy{
					Point: primary.Location(),
					Dst:   arguments[0],
					Src:   arguments[1],
				}
			} else {
				primary = &ast.Call{
					Point: primary.Location(),
					Ref:   vr,
					Exprs: arguments,
				}
			}

		default:
			p.lexer.Unget(t)
			return primary, nil
		}
	}
}

// Operand     = Literal | OperandName | "(" Expression ")" .
// Literal     = BasicLit | CompositeLit | FunctionLit .
// BasicLit    = int_lit | float_lit | imaginary_lit | rune_lit | string_lit .
// OperandName = identifier | QualifiedIdent .
//
// QualifiedIdent = PackageName "." identifier .
//
// CompositeLit  = LiteralType LiteralValue .
// LiteralType   = StructType | ArrayType | "[" "..." "]" ElementType |
//                 SliceType | MapType | TypeName .
// LiteralValue  = "{" [ ElementList [ "," ] ] "}" .
// ElementList   = KeyedElement { "," KeyedElement } .
// KeyedElement  = [ Key ":" ] Element .
// Key           = FieldName | Expression | LiteralValue .
// FieldName     = identifier .
// Element       = Expression | LiteralValue .

func (p *Parser) parseOperand(needLBrace bool) (ast.AST, error) {
	t, err := p.lexer.Get()
	if err != nil {
		return nil, err
	}
	switch t.Type {
	case TConstant: // Literal
		return &ast.BasicLit{
			Point: t.From,
			Value: t.ConstVal,
		}, nil

	case TSymNil:
		return &ast.BasicLit{
			Point: t.From,
		}, nil

	case TIdentifier: // OperandName
		n, err := p.lexer.Get()
		if err != nil {
			return nil, err
		}
		var operandName *ast.VariableRef
		if n.Type == '.' {
			id, err := p.needToken(TIdentifier)
			if err != nil {
				return nil, err
			}
			// QualifiedIdent.
			operandName = &ast.VariableRef{
				Point: t.From,
				Name: ast.Identifier{
					Defined: p.pkg.Name,
					Package: t.StrVal,
					Name:    id.StrVal,
				},
			}
		} else {
			// Identifier in current package.
			p.lexer.Unget(n)
			operandName = &ast.VariableRef{
				Point: t.From,
				Name: ast.Identifier{
					Defined: p.pkg.Name,
					Name:    t.StrVal,
				},
			}
		}
		if needLBrace {
			return operandName, nil
		}

		n, err = p.lexer.Get()
		if err != nil {
			return nil, err
		}
		if n.Type != '{' {
			p.lexer.Unget(n)
			return operandName, nil
		}
		return p.parseCompositeLit(&ast.TypeInfo{
			Point: operandName.Point,
			Type:  ast.TypeName,
			Name:  operandName.Name,
		})

	case '[': // ArrayType LiteralValue
		p.lexer.Unget(t)
		typeInfo, err := p.parseType()
		if err != nil {
			return nil, err
		}
		n, err := p.lexer.Get()
		if err != nil {
			return nil, err
		}
		switch n.Type {
		case '{':
			return p.parseCompositeLit(typeInfo)

		case '(':
			return p.parseArrayCast(n.From, typeInfo)

		default:
			return nil, p.errf(n.From, "unexpected token '%s'", n.Type)
		}

	case '(': // '(' Expression ')'
		expr, err := p.parseExpr(false)
		if err != nil {
			return nil, err
		}
		_, err = p.needToken(')')
		if err != nil {
			return nil, err
		}
		return expr, nil

	default:
		return nil, p.errf(t.From,
			"unexpected token '%s' while parsing expression", t)
	}
}

func (p *Parser) parseArrayCast(loc utils.Point, typeInfo *ast.TypeInfo) (
	ast.AST, error) {
	expr, err := p.parseExpr(false)
	if err != nil {
		return nil, err
	}
	_, err = p.needToken(')')
	if err != nil {
		return nil, err
	}
	return &ast.ArrayCast{
		Point:    loc,
		TypeInfo: typeInfo,
		Expr:     expr,
	}, nil
}

func (p *Parser) toByteArray(expr ast.AST) ([]byte, error) {
	switch val := expr.(type) {
	case *ast.BasicLit:
		switch v := val.Value.(type) {
		case string:
			return []byte(v), nil
		}
	}
	return nil, p.errf(expr.Location(), "cannot convert %s to []byte", expr)
}

func (p *Parser) toRuneArray(expr ast.AST) ([]rune, error) {
	switch val := expr.(type) {
	case *ast.BasicLit:
		switch v := val.Value.(type) {
		case string:
			return []rune(v), nil
		}
	}
	return nil, p.errf(expr.Location(), "cannot convert %s to []rune", expr)
}

func (p *Parser) parseCompositeLit(typeInfo *ast.TypeInfo) (ast.AST, error) {
	n, err := p.lexer.Get()
	p.lexer.Unget(n)

	value, err := p.parseCompositeLitValue(typeInfo)
	if err != nil {
		return nil, err
	}
	return &ast.CompositeLit{
		Point: n.From,
		Type:  typeInfo,
		Value: value,
	}, nil
}

func (p *Parser) parseCompositeLitValue(typeInfo *ast.TypeInfo) (
	[]ast.KeyedElement, error) {

	var value []ast.KeyedElement

	for {
		n, err := p.lexer.Get()
		if err != nil {
			return nil, err
		}
		if n.Type == '}' {
			break
		} else if n.Type == '{' {
			if typeInfo.Type != ast.TypeArray {
				return nil, p.errf(n.From,
					"invalid initializer for type %s", typeInfo)
			}
			v, err := p.parseCompositeLitValue(typeInfo.ElementType)
			if err != nil {
				return nil, err
			}
			value = append(value, ast.KeyedElement{
				Element: &ast.CompositeLit{
					Point: n.From,
					Type:  typeInfo.ElementType,
					Value: v,
				},
			})
		} else {
			p.lexer.Unget(n)
			key, err := p.parseExpr(false)
			if err != nil {
				return nil, err
			}
			n, err = p.lexer.Get()
			if err != nil {
				return nil, err
			}
			var element ast.AST
			if n.Type == ':' {
				element, err = p.parseExpr(false)
				if err != nil {
					return nil, err
				}
			} else {
				p.lexer.Unget(n)
				element = key
				key = nil
			}
			value = append(value, ast.KeyedElement{
				Key:     key,
				Element: element,
			})
		}

		n, err = p.lexer.Get()
		if err != nil {
			return nil, err
		}
		if n.Type == '}' {
			p.lexer.Unget(n)
		} else if n.Type != ',' {
			return nil, p.errf(n.From, "unexpected token %s", n)
		}
	}

	return value, nil
}

// Type      = TypeName | TypeLit | "(" Type ")" .
// TypeName  = identifier | QualifiedIdent .
// TypeLit   = ArrayType | StructType | PointerType | SliceType .
func (p *Parser) parseType() (*ast.TypeInfo, error) {
	t, err := p.lexer.Get()
	if err != nil {
		return nil, err
	}
	switch t.Type {
	case TIdentifier:
		loc := t.From

		var name string
		n, err := p.lexer.Get()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
		} else {
			if n.Type == '.' {
				n, err = p.lexer.Get()
				if err != nil {
					return nil, err
				}
				if n.Type == TIdentifier {
					name = n.StrVal
					loc = n.From
				} else {
					p.lexer.Unget(n)
				}
			} else {
				p.lexer.Unget(n)
			}
		}
		var pkg string
		if len(name) > 0 {
			pkg = t.StrVal
		} else {
			name = t.StrVal
		}
		return &ast.TypeInfo{
			Point: loc,
			Type:  ast.TypeName,
			Name: ast.Identifier{
				Defined: p.pkg.Name,
				Package: pkg,
				Name:    name,
			},
		}, nil

	case '[':
		loc := t.From
		n, err := p.lexer.Get()
		if err != nil {
			return nil, err
		}
		var length ast.AST
		if n.Type != ']' {
			p.lexer.Unget(n)
			length, err = p.parseExpr(false)
			if err != nil {
				return nil, err
			}
			_, err := p.needToken(']')
			if err != nil {
				return nil, err
			}
		}
		elType, err := p.parseType()
		if err != nil {
			return nil, err
		}
		if length != nil {
			return &ast.TypeInfo{
				Point:       loc,
				Type:        ast.TypeArray,
				ElementType: elType,
				ArrayLength: length,
			}, nil
		}
		return &ast.TypeInfo{
			Point:       loc,
			Type:        ast.TypeSlice,
			ElementType: elType,
		}, nil

	case '*':
		elType, err := p.parseType()
		if err != nil {
			return nil, err
		}
		return &ast.TypeInfo{
			Point:       t.From,
			Type:        ast.TypePointer,
			ElementType: elType,
		}, nil

	default:
		return nil, p.errf(t.From,
			"unexpected token '%s' while parsing type", t)
	}
}
