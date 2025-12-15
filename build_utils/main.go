package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type finding struct {
	file   string
	pos    token.Position
	fn     string
	kind   string
	detail string
}

const allowDirective = "buildutils:allow-slice-alias"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: %s <file-or-directory> [...]\n"+
				"Scans Go files for functions that accept slice parameters\n"+
				"and either return them directly or store them in struct fields.\n",
			os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	var files []string
	for _, path := range flag.Args() {
		expanded, err := expandPath(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error enumerating %s: %v\n", path, err)
			os.Exit(1)
		}
		files = append(files, expanded...)
	}

	var allFindings []finding
	for _, file := range files {
		fs := token.NewFileSet()
		f, err := parser.ParseFile(fs, file, nil, parser.ParseComments)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse %s: %v\n", file, err)
			continue
		}
		allFindings = append(allFindings, analyzeFile(fs, file, f)...)
	}

	if len(allFindings) == 0 {
		fmt.Println("No slice-to-struct assignments detected.")
		return
	}

	for _, finding := range allFindings {
		fmt.Printf("%s:%d:%d: [%s] %s in %s\n",
			finding.pos.Filename,
			finding.pos.Line,
			finding.pos.Column,
			finding.kind,
			finding.detail,
			finding.fn,
		)
	}
}

func expandPath(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if shouldIncludeFile(path) {
			return []string{path}, nil
		}
		return nil, nil
	}

	var files []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldIncludeFile(p) {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

func analyzeFile(fs *token.FileSet, filename string, file *ast.File) []finding {
	var findings []finding

	commentMap := ast.NewCommentMap(fs, file, file.Comments)
	commentGroups := file.Comments

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Type == nil || fn.Type.Params == nil {
			continue
		}
		if hasDirective(fs, commentMap, commentGroups, fn) {
			continue
		}

		paramObjs := map[*ast.Object]string{}
		for _, field := range fn.Type.Params.List {
			if hasDirective(fs, commentMap, commentGroups, field) {
				continue
			}
			if isSliceType(field.Type) {
				for _, name := range field.Names {
					if name != nil && name.Obj != nil {
						paramObjs[name.Obj] = name.Name
					}
				}
			}
		}
		if len(paramObjs) == 0 {
			continue
		}

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ReturnStmt:
				if hasDirective(fs, commentMap, commentGroups, node) {
					return true
				}
				for _, result := range node.Results {
					if ident, ok := result.(*ast.Ident); ok {
						if pname, ok := paramObjs[ident.Obj]; ok {
							pos := fs.Position(ident.Pos())
							findings = append(findings, finding{
								file:   filename,
								pos:    pos,
								fn:     fn.Name.Name,
								kind:   "return",
								detail: fmt.Sprintf("returns slice parameter %q", pname),
							})
						}
					}
				}
			case *ast.AssignStmt:
				if hasDirective(fs, commentMap, commentGroups, node) {
					return true
				}
				for i, rhsExpr := range node.Rhs {
					if ident, ok := rhsExpr.(*ast.Ident); ok {
						if pname, ok := paramObjs[ident.Obj]; ok && i < len(node.Lhs) {
							pos := fs.Position(rhsExpr.Pos())
							lhsStr := exprString(node.Lhs[i])
							findings = append(findings, finding{
								file: filename,
								pos:  pos,
								fn:   fn.Name.Name,
								kind: "assignment",
								detail: fmt.Sprintf(
									"assigns slice parameter %q to %s",
									pname,
									lhsStr,
								),
							})
						}
					}
				}
			case *ast.CompositeLit:
				if hasDirective(fs, commentMap, commentGroups, node) {
					return true
				}
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if hasDirective(fs, commentMap, commentGroups, kv) {
						continue
					}
					if ident, ok := kv.Value.(*ast.Ident); ok {
						if pname, ok := paramObjs[ident.Obj]; ok {
							pos := fs.Position(kv.Value.Pos())
							field := exprString(kv.Key)
							findings = append(findings, finding{
								file: filename,
								pos:  pos,
								fn:   fn.Name.Name,
								kind: "struct literal",
								detail: fmt.Sprintf(
									"sets field %s to slice parameter %q",
									field,
									pname,
								),
							})
						}
					}
				}
			}
			return true
		})
	}

	return findings
}

func isSliceType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.ArrayType:
		return t.Len == nil
	case *ast.Ellipsis:
		return true
	}
	return false
}

func hasDirective(
	fs *token.FileSet,
	cm ast.CommentMap,
	groups []*ast.CommentGroup,
	node ast.Node,
) bool {
	if node == nil {
		return false
	}
	if cm != nil {
		if mapped, ok := cm[node]; ok {
			if commentGroupHasDirective(mapped) {
				return true
			}
		}
	}
	nodePos := fs.Position(node.Pos())
	for _, group := range groups {
		for _, c := range group.List {
			if !bytes.Contains([]byte(c.Text), []byte(allowDirective)) {
				continue
			}
			commentPos := fs.Position(c.Slash)
			if commentPos.Filename != nodePos.Filename {
				continue
			}
			if commentPos.Line == nodePos.Line {
				return true
			}
			if commentPos.Line+1 == nodePos.Line && commentPos.Column == 1 {
				return true
			}
		}
	}
	return false
}

func commentGroupHasDirective(groups []*ast.CommentGroup) bool {
	for _, group := range groups {
		for _, c := range group.List {
			if bytes.Contains([]byte(c.Text), []byte(allowDirective)) {
				return true
			}
		}
	}
	return false
}

func exprString(expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	var buf bytes.Buffer
	if err := format.Node(&buf, token.NewFileSet(), expr); err != nil {
		return ""
	}
	return buf.String()
}
func shouldIncludeFile(path string) bool {
	if filepath.Ext(path) != ".go" {
		return false
	}
	name := filepath.Base(path)
	if strings.HasSuffix(name, "_test.go") {
		return false
	}
	return true
}
