package backup

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configure node backup S3-compatible storage",
	Long: `Interactively configure the S3-compatible storage used by
` + "`qclient node backup`" + `. Values are persisted in the qclient config.

Prompts for:
  - access key ID
  - secret access key (hidden)
  - endpoint      (default: ` + utils.DefaultBackupEndpoint + `)
  - bucket        (required, no default)
  - bucket prefix (optional, e.g. "quilibrium/backups"; empty = bucket root)
  - region        (default: ` + utils.DefaultBackupRegion + `)
  - path-style    (default: true)`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

var configPrintCmd = &cobra.Command{
	Use:   "print",
	Short: "Print the current node backup configuration",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
		b := cfg.Backup
		fmt.Printf("Enabled:           %v\n", b.Enabled)
		fmt.Printf("Access Key ID:     %s\n", maskCred(b.AccessKeyID))
		fmt.Printf("Secret Access Key: %s\n", maskCred(b.SecretAccessKey))
		endpoint := b.Endpoint
		if endpoint == "" {
			endpoint = utils.DefaultBackupEndpoint + " (default)"
		}
		fmt.Printf("Endpoint:          %s\n", endpoint)
		bucket := b.Bucket
		if bucket == "" {
			bucket = "(unset)"
		}
		fmt.Printf("Bucket:            %s\n", bucket)
		bucketPrefix := b.BucketPrefix
		if bucketPrefix == "" {
			bucketPrefix = "(none — store at bucket root)"
		}
		fmt.Printf("Bucket Prefix:     %s\n", bucketPrefix)
		region := b.Region
		if region == "" {
			region = utils.DefaultBackupRegion + " (default)"
		}
		fmt.Printf("Region:            %s\n", region)
		fmt.Printf("Use Path Style:    %v\n", b.UsePathStyle)
	},
}

func init() {
	configCmd.AddCommand(configPrintCmd)
}

func runConfig() error {
	cfg, err := utils.LoadClientConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	b := cfg.Backup

	reader := bufio.NewReader(os.Stdin)

	accessKey, err := promptString(reader, "Access Key ID", b.AccessKeyID, true)
	if err != nil {
		return err
	}
	secret, err := promptSecret("Secret Access Key", b.SecretAccessKey != "")
	if err != nil {
		return err
	}
	if secret == "" {
		secret = b.SecretAccessKey
	}
	endpoint, err := promptString(reader, "Endpoint", firstNonEmpty(b.Endpoint, utils.DefaultBackupEndpoint), false)
	if err != nil {
		return err
	}
	bucket, err := promptString(reader, "Bucket", b.Bucket, true)
	if err != nil {
		return err
	}
	bucketPrefix, err := promptString(reader, "Bucket Prefix (optional, blank for none)", b.BucketPrefix, false)
	if err != nil {
		return err
	}
	bucketPrefix = normalizeBucketPrefix(bucketPrefix)
	region, err := promptString(reader, "Region", firstNonEmpty(b.Region, utils.DefaultBackupRegion), false)
	if err != nil {
		return err
	}
	defaultPathStyle := utils.DefaultBackupUsePathStyle
	if b.Bucket != "" || b.AccessKeyID != "" {
		defaultPathStyle = b.UsePathStyle
	}
	usePathStyle, err := promptBool(reader, "Use path-style addressing", defaultPathStyle)
	if err != nil {
		return err
	}

	cfg.Backup = utils.NodeBackupConfig{
		Enabled:         b.Enabled,
		AccessKeyID:     accessKey,
		SecretAccessKey: secret,
		Endpoint:        endpoint,
		Bucket:          bucket,
		BucketPrefix:    bucketPrefix,
		Region:          region,
		UsePathStyle:    usePathStyle,
	}

	if err := utils.SaveClientConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Println("Backup configuration saved.")

	if ok, err := verifyBucket(&cfg.Backup); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not verify bucket access: %v\n", err)
	} else if ok {
		fmt.Printf("Verified access to bucket %q.\n", cfg.Backup.Bucket)
	}

	return nil
}

func promptString(r *bufio.Reader, label, def string, required bool) (string, error) {
	for {
		if def != "" {
			fmt.Printf("%s [%s]: ", label, def)
		} else if required {
			fmt.Printf("%s (required): ", label)
		} else {
			fmt.Printf("%s: ", label)
		}
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			line = def
		}
		if required && line == "" {
			fmt.Println("  value is required")
			continue
		}
		return line, nil
	}
}

func promptSecret(label string, hasExisting bool) (string, error) {
	if hasExisting {
		fmt.Printf("%s [keep existing, press enter to keep]: ", label)
	} else {
		fmt.Printf("%s: ", label)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	buf, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf)), nil
}

func promptBool(r *bufio.Reader, label string, def bool) (bool, error) {
	defStr := "y"
	if !def {
		defStr = "n"
	}
	for {
		fmt.Printf("%s [y/n] (default %s): ", label, defStr)
		line, err := r.ReadString('\n')
		if err != nil {
			return false, err
		}
		line = strings.ToLower(strings.TrimSpace(line))
		switch line {
		case "":
			return def, nil
		case "y", "yes", "true", "1":
			return true, nil
		case "n", "no", "false", "0":
			return false, nil
		default:
			fmt.Println("  please answer y or n")
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// maskCred shows the first 4 characters of a credential and masks the
// rest. Short credentials (<=4 chars) are fully masked.
func maskCred(s string) string {
	if s == "" {
		return "(unset)"
	}
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-4)
}

// verifyBucket attempts a HeadBucket call against the configured
// endpoint to confirm the credentials and bucket are usable.
func verifyBucket(b *utils.NodeBackupConfig) (bool, error) {
	client, err := newS3Client(b)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(b.Bucket)})
	if err != nil {
		return false, err
	}
	return true, nil
}

func newS3Client(b *utils.NodeBackupConfig) (*s3.Client, error) {
	region := b.Region
	if region == "" {
		region = utils.DefaultBackupRegion
	}
	cfg, err := awsconfig.LoadDefaultConfig(
		context.Background(),
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(b.AccessKeyID, b.SecretAccessKey, ""),
		),
	)
	if err != nil {
		return nil, err
	}
	opts := []func(*s3.Options){
		func(o *s3.Options) {
			o.UsePathStyle = b.UsePathStyle
		},
	}
	if b.Endpoint != "" {
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(b.Endpoint)
		})
	}
	return s3.NewFromConfig(cfg, opts...), nil
}
