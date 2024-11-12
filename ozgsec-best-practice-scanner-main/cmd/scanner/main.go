package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/lmittmann/tint"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"

	"github.com/rabbitmq/amqp091-go"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/cache"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/httpclient"

	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/monitoring"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/scanner"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/tlsclient"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/transformer"
	"gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/utils"

	_ "net/http/pprof" // nolint
)

// InitLogger initializes the logger with a tint handler.
// tint is a simple logging library that allows to add colors to the log output.
// this is obviously not required, but it makes the logs easier to read.
func initLogger(logLevel *slog.LevelVar) {
	loggingHandler := tint.NewHandler(os.Stdout, &tint.Options{
		AddSource: true,
		// Level should be set to the env variable LOG_LEVEL defaulting to debug
		Level: logLevel,
	})
	logger := slog.New(loggingHandler)
	slog.SetDefault(logger)
}

type cacher[T any] interface {
	// Get returns the value for the given key.
	Get(ctx context.Context, key string) (T, error)
	// Set sets the value for the given key.
	Set(ctx context.Context, key string, value T, expires time.Duration) error
	// Delete deletes the value for the given key.
	Delete(ctx context.Context, key string) error
}

type responseTransformer interface {
	Transform(input scanner.ScanResponse) ([]byte, error) // the byte array will be passed as response body to the client
}

type tlsClient interface {
	Get(ctx context.Context, target *url.URL, tlsConfig *tls.Config) (net.Conn, error)
}

type httpClient interface {
	Get(ctx context.Context, target *url.URL) (resp httpclient.Response, err error)
}

type monitor interface {
	Write(m monitoring.Monitorable) error
}

type webScanner interface {
	Scan(ctx context.Context, target string, options scanner.TargetScanOptions) scanner.ScanResponse
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

var globalCache cacher[any]

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		randomNumber, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[randomNumber.Int64()]
	}
	return string(b)
}

func failOnError(err error, msg string) {
	if err != nil {
		panic(fmt.Sprintf("%s: %s", msg, err.Error()))
	}
}

type config struct {
	Target        string                   `json:"target"`
	Refresh       bool                     `json:"refresh"`     // if true, the cache will be ignored
	Socks5Proxy   string                   `json:"socks5Proxy"` // if set, the socks5 proxy will be used for the scan
	EnabledChecks []scanner.AnalysisRuleId `json:"enabledChecks"`
}

type rmqMessage struct {
	Data    config `json:"data"`
	Pattern string `json:"pattern"`
}

func registerRMQHandler(responseTransformer responseTransformer, subch *amqp091.Channel, pubch *amqp091.Channel, q amqp091.Queue, monitor monitor, scanner webScanner) {
	consumerTag := fmt.Sprintf("best-practices-scanner-%s", randSeq(4))
	err := subch.Qos(50, 0, false)
	failOnError(err, "failed to set QoS")

	msgs, err := subch.Consume(q.Name, consumerTag, false, false, false, false, nil)
	failOnError(err, "failed toregister a consumer")

	for d := range msgs {
		go func(d amqp091.Delivery) {
			var msg rmqMessage
			err := json.Unmarshal(d.Body, &msg)
			if err != nil {
				slog.Error("could not unmarshal amqp message body", "err", err)
				d.Reject(true) // nolint
				return
			}

			slog.Info("started scan", "target", msg.Data.Target, "requestId", d.MessageId)

			// measure the execution and blocking time of this function
			// this is only for debugging purposes and should be deleted in the future
			start := time.Now()
			timeMeasurementCtx, cancel := context.WithCancel(context.Background())
			// cancel the measurement after the function returns
			defer cancel()
			go func() {
				for {
					select {
					case <-timeMeasurementCtx.Done():
						return
					case <-time.After(20 * time.Second): // this should NEVER happen - a scan can only take 15 seconds max
						slog.Error("still working on message", "messageId", d.MessageId, "requestId", d.MessageId, "target", msg.Data.Target, "duration", time.Since(start).Milliseconds())
					}
				}
			}()

			res := doWork(scanner, msg.Data)

			monitor.Write(res) // nolint // there is nothing we can do
			slog.Info("scan finished", "target", msg.Data.Target, "duration", res.Duration, "requestId", d.MessageId)

			bytes, err := responseTransformer.Transform(res)
			if err != nil {
				slog.Error("could not transform scan result into desired response format", "err", err)
				d.Reject(true) // nolint // if this fails, there is nothing we can do
				return
			}

			replyTo := "scan-response"
			if d.ReplyTo != "" {
				replyTo = d.ReplyTo
			}

			err = pubch.Publish(
				"",      // exchange,
				replyTo, // routing key
				false,   // mandatory
				false,   // immediate
				amqp091.Publishing{
					ContentType: "application/json",
					Body:        bytes,
					Priority:    d.Priority,
					MessageId:   d.MessageId,
				})
			if err != nil {
				slog.Error("failed to publish message", "err", err)
			}
			d.Ack(false) // nolint // if this fails, there is nothing we can do
		}(d)

	}
}

func doWork(sc webScanner, req config) scanner.ScanResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	options := applyConfig(req)
	res := sc.Scan(ctx, req.Target, options)

	return res
}

func rmqHandler(responseTransformer responseTransformer, scanner webScanner, monitor monitor, subch *amqp091.Channel, pubch *amqp091.Channel) {
	q, err := subch.QueueDeclare(
		"scan-request", // name
		true,           // durable
		false,          // delete when unused
		false,          // exclusive
		false,          // no-wait
		amqp091.Table{
			"x-max-priority": 10,
		}, // arguments
	)
	failOnError(err, "failed to declare a queue")
	registerRMQHandler(responseTransformer, subch, pubch, q, monitor, scanner)
}

// checks can be enabled and disabled on a target base.
// if the request does not define which checks should be enabled, it will be read from a config file
var defaultEnabledChecks map[scanner.AnalysisRuleId]bool

func getDefaultChecks() map[scanner.AnalysisRuleId]bool {
	if defaultEnabledChecks != nil {
		return defaultEnabledChecks
	}
	defaultEnabledChecks = make(map[scanner.AnalysisRuleId]bool)
	config := viper.Get("enabledChecks")
	if config == nil || len(config.([]interface{})) == 0 {
		slog.Debug("no enabled checks found in config, enabling all checks")
		for _, check := range scanner.AllChecks {
			defaultEnabledChecks[check] = true
		}
		return defaultEnabledChecks
	}

	enabledChecks := config.([]interface{})
	for _, check := range enabledChecks {
		defaultEnabledChecks[scanner.AnalysisRuleId(check.(string))] = true
	}
	return defaultEnabledChecks
}

func applyConfig(config config) scanner.TargetScanOptions {
	c := globalCache
	if config.Refresh {
		c = cache.NewRefreshCache(globalCache)
	}

	var tlsClient tlsClient
	var httpClient httpClient

	if config.Socks5Proxy != "" {
		socks5ProxyUrl, err := url.Parse("socks5://" + config.Socks5Proxy)
		if err != nil {
			slog.Debug("could not parse socks5 url", "err", err)
			return scanner.TargetScanOptions{}
		}
		slog.Debug("using socks5 proxy", "socks5Url", socks5ProxyUrl.String())
		httpClient = httpclient.NewRedirectAwareHttpClient(&http.Transport{
			IdleConnTimeout: 5 * time.Second,
			Proxy: func(r *http.Request) (*url.URL, error) {
				slog.Debug("proxying request", "requestUrl", r.URL.String())
				return socks5ProxyUrl, nil
			},
			OnProxyConnectResponse: func(ctx context.Context, proxyURL *url.URL, connectReq *http.Request, connectRes *http.Response) error {
				slog.Debug("proxy connect response", "statusCode", connectRes.StatusCode)
				return fmt.Errorf("proxy connect response: %d", connectRes.StatusCode)
			},
		})
		tlsClient = tlsclient.NewSOCKS5(socks5ProxyUrl)
	} else {
		slog.Debug("using no proxy")
		// build the client without any proxy configuration
		tlsClient = tlsclient.NewDefaultClient()
		httpClient = httpclient.NewRedirectAwareHttpClient(&http.Transport{
			IdleConnTimeout: 5 * time.Second,
		})
	}

	enabledChecksMap := make(map[scanner.AnalysisRuleId]bool)
	if config.EnabledChecks != nil {
		slog.Debug("enabled checks", "checks", config.EnabledChecks)
		for _, check := range config.EnabledChecks {
			enabledChecksMap[check] = true
		}
	} else {
		enabledChecksMap = getDefaultChecks()
	}

	return scanner.TargetScanOptions{
		CachingLayer:  c,
		HttpClient:    httpClient,
		TlsClient:     tlsClient,
		EnabledChecks: enabledChecksMap,
	}
}

func parseQueryParams(u *url.URL) (string, scanner.TargetScanOptions) {
	targetURI := u.Query().Get("target")
	refresh := u.Query().Get("refresh") == "true"
	// if the socks5Proxy query parameter is set, it will be used as a proxy for the scanning process.
	// this is helpful to avoid IP-Blocking etc.
	socks5Proxy := u.Query().Get("socks5Proxy")
	return targetURI, applyConfig(config{
		Target:      targetURI,
		Refresh:     refresh,
		Socks5Proxy: socks5Proxy,
	})
}

func handlerFactory(responseTransformer responseTransformer, sc webScanner, monitor monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		/*defer func() {
			if r := recover(); r != nil {
				log.Error(r)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()*/
		targetURI, targetScanOptions := parseQueryParams(r.URL)
		if targetURI == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("target parameter missing")) // nolint // if this fails, there is nothing we can do
			return
		}
		// do a simple http request to check what URL we are actually looking at
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		start := time.Now()
		res := sc.Scan(ctx, targetURI, targetScanOptions)

		monitor.Write(res) // nolint // there is nothing we can do

		slog.Info("scan finished", "target", res.Target, "duration", time.Since(start).String())

		bytes, err := responseTransformer.Transform(res)
		if err != nil {
			slog.Error("could not transform scan results to desired response format", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(bytes) // nolint // if this fails, there is nothing we can do
	}
}

func connectToRabbitMQ(responseTransformer responseTransformer, scanner webScanner, monitor monitor) {

	rmqUsername := os.Getenv("RABBITMQ_USER")
	rmqPassword := os.Getenv("RABBITMQ_PASS")
	rmqHost := os.Getenv("RABBITMQ_HOST")
	rmqPort := os.Getenv("RABBITMQ_PORT")
	rmqRetries := os.Getenv("RABBITMQ_CONNECTION_RETRIES")
	retries, err := strconv.ParseInt(rmqRetries, 10, 64)
	if err != nil {
		slog.Warn("failed to parse environment variable RABBITMQ_CONNECTION_RETRIES to int64. Using 1 retry as fallback", "err", err)
		retries = 0
	}

	conn, err := establishRabbitMQConnection(rmqUsername, rmqPassword, rmqHost, rmqPort, retries)
	if err != nil {
		slog.Error("failed to connect to RabbitMQ, starting without listening to a work queue", "err", err)
		return
	}

	defer conn.Close()

	subch, err := conn.Channel()
	failOnError(err, "failed to open a channel")
	defer subch.Close()
	pubch, err := conn.Channel()

	failOnError(err, "failed to open a channel")
	defer pubch.Close()

	notifyConnClose := conn.NotifyClose(make(chan *amqp091.Error))
	notifySubClose := subch.NotifyClose(make(chan *amqp091.Error))
	notifyPubClose := pubch.NotifyClose(make(chan *amqp091.Error))
	go func() {
		for {
			// just panic on error - this will restart the pod, which will finally lead to a reconnect
			select {
			case err := <-notifyConnClose:
				panic(err)
			case err := <-notifySubClose:
				panic(err)
			case err := <-notifyPubClose:
				panic(err)
			}
		}
	}()

	rmqHandler(responseTransformer, scanner, monitor, subch, pubch)

	forever := make(chan bool)
	<-forever
}

func establishRabbitMQConnection(rmqUsername string, rmqPassword string, rmqHost string, rmqPort string, retries int64) (*amqp091.Connection, error) {
	conn, err := amqp091.Dial(fmt.Sprintf("amqp://%s:%s@%s:%s/", rmqUsername, rmqPassword, rmqHost, rmqPort))
	if err != nil {
		slog.Error("failed to connect to RabbitMQ", "retries", retries, "err", err)
		time.Sleep(10 * time.Second)
		if retries > 0 {
			conn, err = establishRabbitMQConnection(rmqUsername, rmqPassword, rmqHost, rmqPort, retries-1)
		}
	} else {
		slog.Info("successfully connected to RabbitMQ")
	}
	return conn, err
}

func readConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/best-practices-scanner/")
	viper.AddConfigPath("$HOME/.best-pracitces-scanner")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		slog.Error("failed to read config file", "err", err)
	}
}

func translateLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelDebug
	}
}

func main() {
	logLevel := &slog.LevelVar{}
	initLogger(logLevel)

	readConfig()

	err := godotenv.Load()
	if err != nil {
		slog.Error("error loading .env file", "err", err)
	}

	os.Getenv("LOG_LEVEL")
	logLevel.Set(translateLogLevel(os.Getenv("LOG_LEVEL")))
	metricsInstruction := os.Getenv("METRICS")
	if metricsInstruction == "" {
		// metrics defaults to prometheus
		metricsInstruction = "prometheus"
	}

	globalCache, err = cache.NewRedisCache(
		os.Getenv("REDIS_HOST"),
		"",
		0,
		utils.JsonSerializer[any]{},
	)
	if err != nil {
		slog.Error("failed to create redis cache. falling back to MemoryCache implementation", "err", err)
		globalCache = cache.NewMemoryCache[any]()
	}

	scanner := scanner.NewScanner()
	sarifTransformer := transformer.NewSarifTransformer()

	var monitor monitor
	if metricsInstruction == "influx" {
		monitor = monitoring.NewInflux(os.Getenv("INFLUX_URL"), os.Getenv("INFLUX_TOKEN"), os.Getenv("INFLUX_ORG"), os.Getenv("INFLUX_BUCKET"))
	} else {
		promExporter, err := monitoring.NewPromExporter()
		failOnError(err, "failed to create prometheus exporter")
		monitor = monitoring.NewOTELMonitor(promExporter)
	}

	go connectToRabbitMQ(sarifTransformer, scanner, monitor)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if metricsInstruction == "prometheus" {
		http.Handle("/metrics", promhttp.Handler())
	}

	http.Handle("/", http.HandlerFunc(handlerFactory(sarifTransformer, scanner, monitor)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	slog.Info(fmt.Sprintf("starting http server on port %s", port))
	server := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		ReadHeaderTimeout: 3 * time.Second,
	}

	err = server.ListenAndServe()

	failOnError(err, "failed to start server")
}
