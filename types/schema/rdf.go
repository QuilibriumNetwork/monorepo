package schema

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/deiu/rdf2go"
	"github.com/pkg/errors"
)

type RDFParser interface {
	Validate(document string) (bool, error)
	GetTags(document string) (map[string]*RDFTag, error)
	GetTagsByClass(document string) (map[string]map[string]*RDFTag, error)
	GenerateQCL(document string) (string, error)
}

type TurtleRDFParser struct {
}

type Field struct {
	Name       string
	Type       string
	Size       uint32
	Comment    string
	Annotation string
	RdfType    string
	Order      int
	ClassUrl   rdf2go.Term
}

const RdfNS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
const RdfsNS = "http://www.w3.org/2000/01/rdf-schema#"
const SchemaRepositoryNS = "https://types.quilibrium.com/schema-repository/"
const QCLNS = "https://types.quilibrium.com/qcl/"
const Prefix = "<%s>"
const TupleString = "%s%s"
const NTupleString = "<%s%s>"

var rdfTypeN = fmt.Sprintf(NTupleString, RdfNS, "type")
var rdfsClassN = fmt.Sprintf(NTupleString, RdfsNS, "Class")
var rdfsPropertyN = fmt.Sprintf(NTupleString, RdfsNS, "Property")
var rdfsDomainN = fmt.Sprintf(NTupleString, RdfsNS, "domain")
var rdfsRangeN = fmt.Sprintf(NTupleString, RdfsNS, "range")
var rdfsCommentN = fmt.Sprintf(NTupleString, RdfsNS, "comment")

var rdfType = fmt.Sprintf(TupleString, RdfNS, "type")
var rdfsClass = fmt.Sprintf(TupleString, RdfsNS, "Class")
var rdfsProperty = fmt.Sprintf(TupleString, RdfsNS, "Property")
var rdfsDomain = fmt.Sprintf(TupleString, RdfsNS, "domain")
var rdfsRange = fmt.Sprintf(TupleString, RdfsNS, "range")
var qclSize = fmt.Sprintf(TupleString, QCLNS, "size")
var qclOrder = fmt.Sprintf(TupleString, QCLNS, "order")
var rdfsComment = fmt.Sprintf(TupleString, RdfsNS, "comment")

var (
	QCLUint      = "Uint"
	QCLInt       = "Int"
	QCLByteArray = "ByteArray"
	QCLBoolean   = "Bool"
	QCLString    = "String"
	QCLStruct    = "Struct"
)

var qclRdfTypeMap = map[string]string{
	"Uint":      "uint%d",
	"Int":       "int%d",
	"ByteArray": "[%d]byte",
	"Bool":      "bool",
	"String":    "string",
	"Struct":    "struct",
}

func (t *TurtleRDFParser) Validate(document string) (bool, error) {
	g := rdf2go.NewGraph("https://types.quilibrium.com/schema-repository/")
	reader := strings.NewReader(document)
	err := g.Parse(reader, "text/turtle")
	if err != nil {
		return false, errors.Wrap(err, "validate")
	}

	return true, nil
}

func (t *TurtleRDFParser) GetTags(document string) (map[string]*RDFTag, error) {
	g := rdf2go.NewGraph("https://types.quilibrium.com/schema-repository/")
	reader := strings.NewReader(document)
	err := g.Parse(reader, "text/turtle")
	if err != nil {
		return nil, errors.Wrap(err, "get tags")
	}

	prefixMap := make(map[string]string)

	for _, line := range strings.Split(document, "\n") {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "@prefix") ||
			strings.HasPrefix(trimmedLine, "PREFIX") {
			// Parse @prefix or PREFIX lines
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 3 {
				prefix := strings.TrimSuffix(parts[1], ":")
				url := strings.Trim(parts[2], "<>")
				// Don't add trailing slash if URL ends with #
				if !strings.HasSuffix(url, "/") && !strings.HasSuffix(url, "#") {
					url += "/"
				}
				prefixMap[url] = prefix + ":"
			}
		}
	}

	iter := g.IterTriples()
	classes := []string{}
	classTerms := []rdf2go.Term{}
	classUrls := []string{}
	fields := make(map[string]map[string]*Field)
	for a := range iter {
		if a.Predicate.String() == rdfTypeN &&
			a.Object.String() == rdfsClassN {
			subj := a.Subject.RawValue()
			parts := strings.Split(subj, "#")
			className := parts[len(parts)-1]
			parts = strings.Split(className, "/")
			className = parts[len(parts)-1]
			classUrl := subj[:len(subj)-len(className)]

			// Add prefix to className
			// Try with trailing slash first (common case)
			if prefix, ok := prefixMap[classUrl]; ok {
				className = prefix + className
			} else if prefix, ok := prefixMap[classUrl+"/"]; ok {
				// Try adding slash if not found
				className = prefix + className
			}

			classes = append(classes, className)
			classUrls = append(classUrls, classUrl)
			classTerms = append(classTerms, a.Subject)
		}
	}

	for i, c := range classTerms {
		for _, prop := range g.All(nil, rdf2go.NewResource(rdfsRange), c) {
			subj := prop.Subject.RawValue()
			parts := strings.Split(subj, "#")
			className := parts[len(parts)-1]
			parts = strings.Split(className, "/")
			className = parts[len(parts)-1]
			classUrl := subj[:len(subj)-len(className)]
			if _, ok := fields[classes[i]]; !ok {
				fields[classes[i]] = make(map[string]*Field)
			}

			// Debug: Check what prefix we found
			prefix := ""
			if p, ok := prefixMap[classUrl]; ok {
				prefix = p
			}

			fields[classes[i]][className] = &Field{
				Name:       className,
				ClassUrl:   prop.Subject,
				Annotation: prefix + className,
				Order:      -1,
			}
		}
	}

	for _, class := range fields {
		for fieldName, field := range class {
			// scan the types
			for _, prop := range g.All(field.ClassUrl, rdf2go.NewResource(
				rdfsDomain,
			), nil) {
				obj := prop.Object.RawValue()
				parts := strings.Split(obj, "#")
				className := parts[len(parts)-1]
				parts = strings.Split(className, "/")
				className = parts[len(parts)-1]
				classUrl := obj[:len(obj)-len(className)]
				switch classUrl {
				case QCLNS:
					field.Type = qclRdfTypeMap[className]
					field.RdfType = className

					// Bool type has implicit size of 1
					if className == "Bool" {
						field.Size = 1
					} else {
						// Process size for other types
						for _, sprop := range g.All(field.ClassUrl, rdf2go.NewResource(
							qclSize,
						), nil) {
							sobj := sprop.Object.RawValue()
							parts := strings.Split(sobj, "#")
							size := parts[len(parts)-1]
							parts = strings.Split(size, "/")
							size = parts[len(parts)-1]
							s, err := strconv.Atoi(size)
							fieldSize := s
							if className != "String" && className != "ByteArray" &&
								className != "Struct" {
								fieldSize *= 8
							}
							if err != nil || s < 1 {
								return nil, errors.Wrap(
									fmt.Errorf(
										"invalid size for %s: %s",
										fieldName,
										size,
									),
									"get tags",
								)
							}
							if strings.Contains(field.Type, "%") {
								field.Type = fmt.Sprintf(field.Type, fieldSize)
							}
							field.Size = uint32(s)
						}
						if strings.Contains(field.Type, "%d") {
							return nil, errors.Wrap(
								fmt.Errorf(
									"size unspecified for %s, add a qcl:size predicate",
									fieldName,
								),
								"get tags",
							)
						}
					}
				case RdfsNS:
					if className != "Literal" {
						return nil, errors.Wrap(
							fmt.Errorf(
								"invalid property type for %s: %s",
								fieldName,
								className,
							),
							"get tags",
						)
					}
					field.Type = className
				default:
					field.Type = "hypergraph.Extrinsic"
					field.Annotation += ",extrinsic=" + prefixMap[classUrl] + className
					field.Size = 32
					field.RdfType = "Struct"
				}
				break
			}

			// Check if size is required but not specified
			if field.RdfType == "String" && field.Size == 0 {
				return nil, errors.Wrap(
					fmt.Errorf(
						"size unspecified for %s, add a qcl:size predicate",
						fieldName,
					),
					"get tags",
				)
			}

			for _, sprop := range g.All(field.ClassUrl, rdf2go.NewResource(
				qclOrder,
			), nil) {
				sobj := sprop.Object.RawValue()
				parts := strings.Split(sobj, "#")
				order := parts[len(parts)-1]
				parts = strings.Split(order, "/")
				order = parts[len(parts)-1]
				o, err := strconv.Atoi(order)
				fieldOrder := o
				if err != nil || o < 0 || o > MaxOrderThreeByte {
					return nil, errors.Wrap(
						fmt.Errorf(
							"invalid order for %s: %s (must be between 0 and %d)",
							fieldName,
							order,
							MaxOrderThreeByte,
						),
						"get tags",
					)
				}
				field.Order = fieldOrder
			}
			if field.Order < 0 {
				return nil, errors.Wrap(
					fmt.Errorf(
						"field order unspecified for %s, add a qcl:order predicate",
						fieldName,
					),
					"get tags",
				)
			}

			for _, prop := range g.All(field.ClassUrl, rdf2go.NewResource(
				rdfsComment,
			), nil) {
				field.Comment = prop.Object.String()
			}
		}
	}

	// Convert fields to RDFTag format
	tags := make(map[string]*RDFTag)

	// Process each class
	for _, class := range classes {
		classFields := fields[class]

		for fieldName, field := range classFields {
			// Build the RDF tag
			tagParts := []string{field.Annotation}

			// Add order
			tagParts = append(tagParts, fmt.Sprintf("order=%d", field.Order))

			// Add size for fields that need it
			needsSize := false
			switch field.RdfType {
			case "String", "ByteArray":
				needsSize = true
			case "Struct":
				// Only add size for non-Extrinsic structs
				if field.Type != "hypergraph.Extrinsic" {
					needsSize = true
				}
			}

			if needsSize && field.Size > 0 {
				tagParts = append(tagParts, fmt.Sprintf("size=%d", field.Size))
			}

			// Create RDFTag
			tag := &RDFTag{
				Order:     field.Order,
				RdfType:   field.RdfType,
				FieldSize: field.Size,
			}

			// Handle the name and extrinsic for hypergraph.Extrinsic fields
			if field.Type == "hypergraph.Extrinsic" &&
				strings.Contains(field.Annotation, ",extrinsic=") {
				// Extract name and extrinsic value from annotation
				parts := strings.Split(field.Annotation, ",extrinsic=")
				if len(parts) == 2 {
					tag.Name = parts[0]
					tag.Extrinsic = parts[1]
				}
			} else {
				tag.Name = field.Annotation
			}

			// Set size if needed
			if field.Size > 0 && needsSize {
				// Set size only for fields that need it in the tag
				size := int(field.Size)
				tag.Size = &size
			}

			// Set raw tag value - always use the constructed tagParts
			tag.Raw = strings.Join(tagParts, ",")

			tags[fieldName] = tag
		}
	}

	return tags, nil
}

func (t *TurtleRDFParser) GetTagsByClass(document string) (
	map[string]map[string]*RDFTag,
	error,
) {
	g := rdf2go.NewGraph("https://types.quilibrium.com/schema-repository/")
	reader := strings.NewReader(document)
	err := g.Parse(reader, "text/turtle")
	if err != nil {
		return nil, errors.Wrap(err, "get tags by class")
	}

	prefixMap := make(map[string]string)

	for _, line := range strings.Split(document, "\n") {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "@prefix") ||
			strings.HasPrefix(trimmedLine, "PREFIX") {
			// Parse @prefix or PREFIX lines
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 3 {
				prefix := strings.TrimSuffix(parts[1], ":")
				url := strings.Trim(parts[2], "<>")
				// Don't add trailing slash if URL ends with #
				if !strings.HasSuffix(url, "/") && !strings.HasSuffix(url, "#") {
					url += "/"
				}
				prefixMap[url] = prefix + ":"
			}
		}
	}

	iter := g.IterTriples()
	classes := []string{}
	classTerms := []rdf2go.Term{}
	classUrls := []string{}
	fields := make(map[string]map[string]*Field)
	for a := range iter {
		if a.Predicate.String() == rdfTypeN &&
			a.Object.String() == rdfsClassN {
			subj := a.Subject.RawValue()
			parts := strings.Split(subj, "#")
			className := parts[len(parts)-1]
			parts = strings.Split(className, "/")
			className = parts[len(parts)-1]
			classUrl := subj[:len(subj)-len(className)]
			// Add prefix to className
			// Try with trailing slash first (common case)
			if prefix, ok := prefixMap[classUrl]; ok {
				className = prefix + className
			} else if prefix, ok := prefixMap[classUrl+"/"]; ok {
				// Try adding slash if not found
				className = prefix + className
			}

			classes = append(classes, className)
			classUrls = append(classUrls, classUrl)
			classTerms = append(classTerms, a.Subject)
		}
	}

	for i, c := range classTerms {
		for _, prop := range g.All(nil, rdf2go.NewResource(rdfsRange), c) {
			subj := prop.Subject.RawValue()
			parts := strings.Split(subj, "#")
			propertyName := parts[len(parts)-1]
			parts = strings.Split(propertyName, "/")
			propertyName = parts[len(parts)-1]
			propertyUrl := subj[:len(subj)-len(propertyName)]
			if _, ok := fields[classes[i]]; !ok {
				fields[classes[i]] = make(map[string]*Field)
			}

			// Debug: Check what prefix we found
			prefix := ""
			if p, ok := prefixMap[propertyUrl]; ok {
				prefix = p
			}

			fields[classes[i]][propertyName] = &Field{
				Name:       propertyName,
				ClassUrl:   prop.Subject,
				Annotation: prefix + propertyName,
				Order:      -1,
			}
		}
	}

	for _, class := range fields {
		for fieldName, field := range class {
			// scan the types
			for _, prop := range g.All(field.ClassUrl, rdf2go.NewResource(
				rdfsDomain,
			), nil) {
				obj := prop.Object.RawValue()
				parts := strings.Split(obj, "#")
				className := parts[len(parts)-1]
				parts = strings.Split(className, "/")
				className = parts[len(parts)-1]
				classUrl := obj[:len(obj)-len(className)]
				switch classUrl {
				case QCLNS:
					field.Type = qclRdfTypeMap[className]
					field.RdfType = className

					// Bool type has implicit size of 1
					if className == "Bool" {
						field.Size = 1
					} else {
						// Process size for other types
						for _, sprop := range g.All(field.ClassUrl, rdf2go.NewResource(
							qclSize,
						), nil) {
							sobj := sprop.Object.RawValue()
							parts := strings.Split(sobj, "#")
							size := parts[len(parts)-1]
							parts = strings.Split(size, "/")
							size = parts[len(parts)-1]
							s, err := strconv.Atoi(size)
							fieldSize := s
							if className != "String" && className != "ByteArray" &&
								className != "Struct" {
								fieldSize *= 8
							}
							if err != nil || s < 1 {
								return nil, errors.Wrap(
									fmt.Errorf(
										"invalid size for %s: %s",
										fieldName,
										size,
									),
									"get tags by class",
								)
							}
							if strings.Contains(field.Type, "%") {
								field.Type = fmt.Sprintf(field.Type, fieldSize)
							}
							field.Size = uint32(s)
						}
						if strings.Contains(field.Type, "%d") {
							return nil, errors.Wrap(
								fmt.Errorf(
									"size unspecified for %s, add a qcl:size predicate",
									fieldName,
								),
								"get tags by class",
							)
						}
					}
				case RdfsNS:
					if className != "Literal" {
						return nil, errors.Wrap(
							fmt.Errorf(
								"invalid property type for %s: %s",
								fieldName,
								className,
							),
							"get tags by class",
						)
					}
					field.Type = className
				default:
					field.Type = "hypergraph.Extrinsic"
					field.Annotation += ",extrinsic=" + prefixMap[classUrl] + className
					field.Size = 32
					field.RdfType = "Struct"
				}
				break
			}

			// Check if size is required but not specified
			if field.RdfType == "String" && field.Size == 0 {
				return nil, errors.Wrap(
					fmt.Errorf(
						"size unspecified for %s, add a qcl:size predicate",
						fieldName,
					),
					"get tags by class",
				)
			}

			for _, sprop := range g.All(field.ClassUrl, rdf2go.NewResource(
				qclOrder,
			), nil) {
				sobj := sprop.Object.RawValue()
				parts := strings.Split(sobj, "#")
				order := parts[len(parts)-1]
				parts = strings.Split(order, "/")
				order = parts[len(parts)-1]
				o, err := strconv.Atoi(order)
				fieldOrder := o
				if err != nil || o < 0 {
					return nil, errors.Wrap(
						fmt.Errorf(
							"invalid order for %s: %s",
							fieldName,
							order,
						),
						"get tags by class",
					)
				}
				field.Order = fieldOrder
			}
			if field.Order < 0 {
				return nil, errors.Wrap(
					fmt.Errorf(
						"field order unspecified for %s, add a qcl:order predicate",
						fieldName,
					),
					"get tags by class",
				)
			}

			for _, prop := range g.All(field.ClassUrl, rdf2go.NewResource(
				rdfsComment,
			), nil) {
				field.Comment = prop.Object.String()
			}
		}
	}

	// Convert fields to RDFTag format, organized by class
	tagsByClass := make(map[string]map[string]*RDFTag)

	// Process each class
	for _, class := range classes {
		classFields := fields[class]
		tags := make(map[string]*RDFTag)

		for fieldName, field := range classFields {
			// Build the RDF tag
			tagParts := []string{field.Annotation}

			// Add order
			tagParts = append(tagParts, fmt.Sprintf("order=%d", field.Order))

			// Add size for fields that need it
			needsSize := false
			switch field.RdfType {
			case "String", "ByteArray":
				needsSize = true
			case "Struct":
				// Only add size for non-Extrinsic structs
				if field.Type != "hypergraph.Extrinsic" {
					needsSize = true
				}
			}

			if needsSize && field.Size > 0 {
				tagParts = append(tagParts, fmt.Sprintf("size=%d", field.Size))
			}

			// Create RDFTag
			tag := &RDFTag{
				Order:     field.Order,
				RdfType:   field.RdfType,
				FieldSize: field.Size,
			}

			// Handle the name and extrinsic for hypergraph.Extrinsic fields
			if field.Type == "hypergraph.Extrinsic" &&
				strings.Contains(field.Annotation, ",extrinsic=") {
				// Extract name and extrinsic value from annotation
				parts := strings.Split(field.Annotation, ",extrinsic=")
				if len(parts) == 2 {
					tag.Name = parts[0]
					tag.Extrinsic = parts[1]
				}
			} else {
				tag.Name = field.Annotation
			}

			// Set size if needed
			if field.Size > 0 && needsSize {
				// Set size only for fields that need it in the tag
				size := int(field.Size)
				tag.Size = &size
			}

			// Set raw tag value - always use the constructed tagParts
			tag.Raw = strings.Join(tagParts, ",")

			tags[fieldName] = tag
		}

		tagsByClass[class] = tags
	}

	return tagsByClass, nil
}

func (t *TurtleRDFParser) GenerateQCL(document string) (string, error) {
	g := rdf2go.NewGraph("https://types.quilibrium.com/schema-repository/")
	reader := strings.NewReader(document)
	err := g.Parse(reader, "text/turtle")
	if err != nil {
		return "", errors.Wrap(err, "validate")
	}

	prefixMap := make(map[string]string)

	for _, line := range strings.Split(document, "\n") {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "@prefix") ||
			strings.HasPrefix(trimmedLine, "PREFIX") {
			// Parse @prefix or PREFIX lines
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 3 {
				prefix := strings.TrimSuffix(parts[1], ":")
				url := strings.Trim(parts[2], "<>")
				// Don't add trailing slash if URL ends with #
				if !strings.HasSuffix(url, "/") && !strings.HasSuffix(url, "#") {
					url += "/"
				}
				prefixMap[url] = prefix + ":"
			}
		}
	}

	iter := g.IterTriples()
	classes := []string{}
	classTerms := []rdf2go.Term{}
	classUrls := []string{}
	fields := make(map[string]map[string]*Field)
	for a := range iter {
		if a.Predicate.String() == rdfTypeN &&
			a.Object.String() == rdfsClassN {
			subj := a.Subject.RawValue()
			parts := strings.Split(subj, "#")
			className := parts[len(parts)-1]
			parts = strings.Split(className, "/")
			className = parts[len(parts)-1]
			classUrl := subj[:len(subj)-len(className)]

			// Add prefix to className
			// Try with trailing slash first (common case)
			if prefix, ok := prefixMap[classUrl]; ok {
				className = prefix + className
			} else if prefix, ok := prefixMap[classUrl+"/"]; ok {
				// Try adding slash if not found
				className = prefix + className
			}

			classes = append(classes, className)
			classUrls = append(classUrls, classUrl)
			classTerms = append(classTerms, a.Subject)
		}
	}

	for i, c := range classTerms {
		for _, prop := range g.All(nil, rdf2go.NewResource(rdfsRange), c) {
			subj := prop.Subject.RawValue()
			parts := strings.Split(subj, "#")
			className := parts[len(parts)-1]
			parts = strings.Split(className, "/")
			className = parts[len(parts)-1]
			classUrl := subj[:len(subj)-len(className)]
			if _, ok := fields[classes[i]]; !ok {
				fields[classes[i]] = make(map[string]*Field)
			}

			// Debug: Check what prefix we found
			prefix := ""
			if p, ok := prefixMap[classUrl]; ok {
				prefix = p
			}

			fields[classes[i]][className] = &Field{
				Name:       className,
				ClassUrl:   prop.Subject,
				Annotation: prefix + className,
				Order:      -1,
			}
		}
	}

	for _, class := range fields {
		for fieldName, field := range class {
			// scan the types
			for _, prop := range g.All(field.ClassUrl, rdf2go.NewResource(
				rdfsDomain,
			), nil) {
				obj := prop.Object.RawValue()
				parts := strings.Split(obj, "#")
				className := parts[len(parts)-1]
				parts = strings.Split(className, "/")
				className = parts[len(parts)-1]
				classUrl := obj[:len(obj)-len(className)]
				switch classUrl {
				case QCLNS:
					field.Type = qclRdfTypeMap[className]
					field.RdfType = className

					// Bool type has implicit size of 1
					if className == "Bool" {
						field.Size = 1
					} else {
						// Process size for other types
						for _, sprop := range g.All(field.ClassUrl, rdf2go.NewResource(
							qclSize,
						), nil) {
							sobj := sprop.Object.RawValue()
							parts := strings.Split(sobj, "#")
							size := parts[len(parts)-1]
							parts = strings.Split(size, "/")
							size = parts[len(parts)-1]
							s, err := strconv.Atoi(size)
							fieldSize := s
							if className != "String" && className != "ByteArray" &&
								className != "Struct" {
								fieldSize *= 8
							}
							if err != nil || s < 1 {
								return "", errors.Wrap(
									fmt.Errorf(
										"invalid size for %s: %s",
										fieldName,
										size,
									),
									"generate qcl",
								)
							}
							if strings.Contains(field.Type, "%") {
								field.Type = fmt.Sprintf(field.Type, fieldSize)
							}
							field.Size = uint32(s)
						}
						if strings.Contains(field.Type, "%d") {
							return "", errors.Wrap(
								fmt.Errorf(
									"size unspecified for %s, add a qcl:size predicate",
									fieldName,
								),
								"generate qcl",
							)
						}
					}
				case RdfsNS:
					if className != "Literal" {
						return "", errors.Wrap(
							fmt.Errorf(
								"invalid property type for %s: %s",
								fieldName,
								className,
							),
							"generate qcl",
						)
					}
					field.Type = className
				default:
					field.Type = "hypergraph.Extrinsic"
					field.Annotation += ",extrinsic=" + prefixMap[classUrl] + className
					field.Size = 32
					field.RdfType = "Struct"
				}
				break
			}

			// Check if size is required but not specified
			if field.RdfType == "String" && field.Size == 0 {
				return "", errors.Wrap(
					fmt.Errorf(
						"size unspecified for %s, add a qcl:size predicate",
						fieldName,
					),
					"generate qcl",
				)
			}

			for _, sprop := range g.All(field.ClassUrl, rdf2go.NewResource(
				qclOrder,
			), nil) {
				sobj := sprop.Object.RawValue()
				parts := strings.Split(sobj, "#")
				order := parts[len(parts)-1]
				parts = strings.Split(order, "/")
				order = parts[len(parts)-1]
				o, err := strconv.Atoi(order)
				fieldOrder := o
				if err != nil || o < 0 {
					return "", errors.Wrap(
						fmt.Errorf(
							"invalid order for %s: %s",
							fieldName,
							order,
						),
						"generate qcl",
					)
				}
				field.Order = fieldOrder
			}
			if field.Order < 0 {
				return "", errors.Wrap(
					fmt.Errorf(
						"field order unspecified for %s, add a qcl:order predicate",
						fieldName,
					),
					"generate qcl",
				)
			}

			for _, prop := range g.All(field.ClassUrl, rdf2go.NewResource(
				rdfsComment,
			), nil) {
				field.Comment = prop.Object.String()
			}
		}
	}

	output := "package main\n\n"

	sort.Slice(classes, func(i, j int) bool {
		return strings.Compare(classes[i], classes[j]) < 0
	})

	for _, class := range classes {
		// Strip prefix for Go struct name
		structName := class
		if colonIdx := strings.Index(class, ":"); colonIdx != -1 {
			structName = class[colonIdx+1:]
		}
		output += fmt.Sprintf("type %s struct {\n", structName)

		sortedFields := []*Field{}
		for _, field := range fields[class] {
			sortedFields = append(sortedFields, field)
		}
		sort.Slice(sortedFields, func(i, j int) bool {
			return sortedFields[i].Order < sortedFields[j].Order
		})
		for _, field := range sortedFields {
			if field.Comment != "" {
				output += fmt.Sprintf("  // %s\n", field.Comment)
			}
			// Build the RDF tag
			tagParts := []string{field.Annotation}

			// Add order
			tagParts = append(tagParts, fmt.Sprintf("order=%d", field.Order))

			// Add size for fields that need it
			needsSize := false
			switch field.RdfType {
			case "String", "ByteArray":
				needsSize = true
			case "Struct":
				// Only add size for non-Extrinsic structs
				if field.Type != "hypergraph.Extrinsic" {
					needsSize = true
				}
			}

			if needsSize && field.Size > 0 {
				tagParts = append(tagParts, fmt.Sprintf("size=%d", field.Size))
			}

			// Always use the constructed tag parts
			output += fmt.Sprintf(
				"  %s %s `rdf:\"%s\"`\n",
				field.Name,
				field.Type,
				strings.Join(tagParts, ","),
			)
		}
		output += "}\n\n"
	}

	for _, class := range classes {
		// Strip prefix for Go struct name
		structName := class
		if colonIdx := strings.Index(class, ":"); colonIdx != -1 {
			structName = class[colonIdx+1:]
		}

		totalSize := uint32(0)
		for _, field := range fields[class] {
			totalSize += field.Size
		}
		output += fmt.Sprintf(
			"func Unmarshal%s(payload [%d]byte) %s {\n  result := %s{}\n",
			structName,
			totalSize,
			structName,
			structName,
		)
		s := uint32(0)
		sortedFields := []*Field{}
		for _, field := range fields[class] {
			sortedFields = append(sortedFields, field)
		}
		sort.Slice(sortedFields, func(i, j int) bool {
			return sortedFields[i].Order < sortedFields[j].Order
		})
		for _, field := range sortedFields {
			sizedType := ""
			switch field.RdfType {
			case "Uint":
				sizedType = fmt.Sprintf(
					"binary.GetUint(payload[%d:%d])",
					s,
					s+field.Size,
				)
				s += field.Size
			case "Int":
				sizedType = fmt.Sprintf(
					"int%d(binary.GetUint(payload[%d:%d]))",
					field.Size*8,
					s,
					s+field.Size,
				)
				s += field.Size
			case "ByteArray":
				sizedType = fmt.Sprintf(
					"payload[%d:%d]",
					s,
					s+field.Size,
				)
				s += field.Size
			case "Bool":
				sizedType = fmt.Sprintf("payload[%d] != 0", s)
				s++
			case "String":
				sizedType = fmt.Sprintf(
					"string(payload[%d:%d])",
					s,
					s+field.Size,
				)
				s += field.Size
			case "Struct":
				sizedType = fmt.Sprintf(
					"hypergraph.Extrinsic{}\n  result.%s.Ref = payload[%d:%d]",
					field.Name,
					s,
					s+field.Size,
				)
				s += field.Size
			}
			output += fmt.Sprintf(
				"  result.%s = %s\n",
				field.Name,
				sizedType,
			)
		}
		output += "  return result\n}\n\n"
	}

	for _, class := range classes {
		// Strip prefix for Go struct name
		structName := class
		if colonIdx := strings.Index(class, ":"); colonIdx != -1 {
			structName = class[colonIdx+1:]
		}

		totalSize := uint32(0)
		for _, field := range fields[class] {
			totalSize += field.Size
		}
		output += fmt.Sprintf(
			"func Marshal%s(obj %s) [%d]byte {\n",
			structName,
			structName,
			totalSize,
		)
		s := uint32(0)
		sortedFields := []*Field{}
		for _, field := range fields[class] {
			sortedFields = append(sortedFields, field)
		}
		sort.Slice(sortedFields, func(i, j int) bool {
			return sortedFields[i].Order < sortedFields[j].Order
		})
		output += fmt.Sprintf("  buf := make([]byte, %d)\n", totalSize)

		for _, field := range sortedFields {
			sizedType := ""
			switch field.RdfType {
			case "Uint":
				sizedType = fmt.Sprintf(
					"binary.PutUint(buf, %d, obj.%s)",
					s,
					field.Name,
				)
				s += field.Size
			case "Int":
				sizedType = fmt.Sprintf(
					"binary.PutInt(buf, %d, obj.%s)",
					s,
					field.Name,
				)
				s += field.Size
			case "ByteArray":
				sizedType = fmt.Sprintf(
					"copy(buf[%d:%d], obj.%s)",
					s,
					s+field.Size,
					field.Name,
				)
				s += field.Size
			case "Bool":
				sizedType = fmt.Sprintf(
					"if obj.%s { buf[%d] = 0xff } else { buf[%d] = 0x00 }",
					field.Name,
					s,
					s,
				)
				s++
			case "String":
				sizedType = fmt.Sprintf(
					"copy(buf[%d:%d], []byte(obj.%s))",
					s,
					s+field.Size,
					field.Name,
				)
				s += field.Size
			case "Struct":
				sizedType = fmt.Sprintf(
					"copy(buf[%d:%d], obj.%s.Ref)",
					s,
					s+field.Size,
					field.Name,
				)
				s += field.Size
			}
			output += fmt.Sprintf(
				"  %s\n",
				sizedType,
			)
		}
		output += "  return buf\n}\n\n"
	}

	return output, nil
}
