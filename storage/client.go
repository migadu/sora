package storage

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/logging"
	"github.com/migadu/sora/logger"
)

// ClientConfig says how to reach an S3-compatible store.
type ClientConfig struct {
	// Endpoint is host[:port] or a URL. Without a scheme, UseTLS picks https or http.
	Endpoint string
	UseTLS   bool
	// Region is the region requests are signed for. Empty takes AWS_REGION or the
	// shared AWS config, else us-east-1, which S3-compatible stores generally accept.
	Region string
	// AccessKey and SecretKey sign the requests. With both empty the AWS default
	// credential chain supplies them: environment, shared credentials file, web
	// identity, container or instance role.
	AccessKey string
	SecretKey string
	// Debug logs every request, response and retry through the logger package.
	Debug bool
	// LogPrefix names the client in the debug log.
	LogPrefix string
}

// Option adjusts the client New builds beyond what its arguments say.
type Option func(*ClientConfig)

// WithRegion sets the region requests are signed for. Empty keeps the default.
func WithRegion(region string) Option {
	return func(c *ClientConfig) { c.Region = region }
}

// NewClient builds an S3 client for cfg. Every request goes to the endpoint as given,
// with path-style addressing, which S3-compatible stores need. optFns adjust the
// client options last.
func NewClient(ctx context.Context, cfg ClientConfig, optFns ...func(*s3.Options)) (*s3.Client, error) {
	endpointURL := cfg.Endpoint
	if !strings.HasPrefix(endpointURL, "http://") && !strings.HasPrefix(endpointURL, "https://") {
		if cfg.UseTLS {
			endpointURL = "https://" + endpointURL
		} else {
			endpointURL = "http://" + endpointURL
		}
	}

	// The SDK's own loader supplies what the configuration leaves out: the region and
	// the credential chain. A bare aws.Config has neither.
	var loadOpts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.Region))
	}
	switch {
	case cfg.AccessKey != "" && cfg.SecretKey != "":
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")))
	case cfg.AccessKey != "" || cfg.SecretKey != "":
		return nil, errors.New("access_key and secret_key must be set together; leave both empty to use the AWS default credential chain")
	}
	if cfg.Debug {
		// ClientLogMode alone selects what to trace; without a logger the SDK discards it.
		loadOpts = append(loadOpts,
			awsconfig.WithClientLogMode(aws.LogRequest|aws.LogResponse|aws.LogRetries),
			awsconfig.WithLogger(debugLogger{prefix: cfg.LogPrefix}))
	} else {
		// The loader's own default logger writes to os.Stderr, past the server log - for
		// one, a warning on every GET from a store that returns no checksum header.
		loadOpts = append(loadOpts, awsconfig.WithLogger(logging.Nop{}))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}
	if awsCfg.Region == "" {
		awsCfg.Region = "us-east-1"
	}
	if cfg.AccessKey == "" {
		// Without keys, a chain that finds nothing would fail every request, each one
		// probing the chain again. Find out now.
		if awsCfg.Credentials == nil {
			return nil, errors.New("no S3 credentials: set access_key and secret_key, or provide them through the AWS default credential chain")
		}
		if _, err := awsCfg.Credentials.Retrieve(ctx); err != nil {
			return nil, fmt.Errorf("no S3 credentials: set access_key and secret_key, or provide them through the AWS default credential chain: %w", err)
		}
	}
	awsCfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(
		func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:               endpointURL,
				HostnameImmutable: true,
				Source:            aws.EndpointSourceCustom,
			}, nil
		})

	optFns = append([]func(*s3.Options){func(o *s3.Options) { o.UsePathStyle = true }}, optFns...)
	return s3.NewFromConfig(awsCfg, optFns...), nil
}

// debugLogger writes the SDK's request and response tracing, which debug = true asks
// for, to the server log. It logs at INFO so that the trace appears without lowering
// the log level of the whole server.
type debugLogger struct {
	prefix string
}

// traceSecrets matches what a request trace carries that a reader of the log could
// use: the SigV4 signature, with which S3 accepts the same request again while its
// X-Amz-Date is recent (a GET of a message body or a certificate key), and the session
// token of credentials from the default chain. The credential scope before the
// signature stays readable, since it shows the key id and the signing region.
var traceSecrets = regexp.MustCompile(`(Signature=)[0-9A-Fa-f]+|((?i)x-amz-security-token: )[^\r\n]+`)

func (l debugLogger) Logf(classification logging.Classification, format string, v ...any) {
	detail := traceSecrets.ReplaceAllString(fmt.Sprintf(format, v...), "${1}${2}[redacted]")
	if classification == logging.Warn {
		logger.Warn(l.prefix+": AWS SDK", "detail", detail)
		return
	}
	logger.Info(l.prefix+": AWS SDK trace", "detail", detail)
}
