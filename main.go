package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"

	httptrace "github.com/DataDog/dd-trace-go/contrib/net/http/v2"
	dd_logrus "github.com/DataDog/dd-trace-go/contrib/sirupsen/logrus/v2"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

var (
	developmentClient *apns2.Client
	productionClient  *apns2.Client
	topic             string
	messageChan       chan *Message
	maxQueueSize      int
	maxWorkers        int
)

func main() {
	err := tracer.Start()
	if err != nil {
		log.Fatal(fmt.Sprintf("Error starting tracer: %s", err))
		return
	}

	httpClient := httptrace.WrapClient(http.DefaultClient)

	mux := httptrace.NewServeMux()

	log.AddHook(&dd_logrus.DDContextLogHook{})

	flag.IntVar(&maxQueueSize, "max-queue-size", 4096, "Maximum number of messages to queue")
	flag.IntVar(&maxWorkers, "max-workers", 8, "Maximum number of workers")
	flag.Parse()

	topic = env("TOPIC", "cx.c3.toot")
	p12file := env("P12_FILENAME", "toot-relay.p12")
	p12base64 := env("P12_BASE64", "")
	p12password := env("P12_PASSWORD", "")

	tokenSignKeyFile := env("TOKEN_AUTH_KEY_FILENAME", "")
	tokenKeyId := env("TOKEN_KEY_ID", "")
	tokenTeamId := env("TOKEN_TEAM_ID", "")

	port := env("PORT", "42069")
	tlsCrtFile := env("CRT_FILENAME", "toot-relay.crt")
	tlsKeyFile := env("KEY_FILENAME", "toot-relay.key")
	// CA_FILENAME can be set to a file that contains PEM encoded certificates that will be
	// used as the sole root CAs when connecting to the Apple Notification Service API.
	// If unset, the system-wide certificate store will be used.
	caFile := env("CA_FILENAME", "")
	var rootCAs *x509.CertPool

	if caPEM, err := os.ReadFile(caFile); err == nil {
		rootCAs = x509.NewCertPool()
		if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
			log.Fatal(fmt.Sprintf("CA file %s specified but no CA certificates could be loaded\n", caFile))
		}
	}

	if tokenSignKeyFile != "" {
		authKey, err := token.AuthKeyFromFile(tokenSignKeyFile)
		if err != nil {
			log.Fatal(fmt.Sprintf("Error loading token auth key %s: %s", tokenSignKeyFile, err))
		}

		token := &token.Token{
			AuthKey: authKey,
			KeyID:   tokenKeyId,
			TeamID:  tokenTeamId,
		}

		developmentClient = apns2.NewTokenClient(token).Development()
		productionClient = apns2.NewTokenClient(token).Production()
	} else if p12base64 != "" {
		bytes, err := base64.StdEncoding.DecodeString(p12base64)
		if err != nil {
			log.Fatal(fmt.Sprintf("Base64 decoding error: %s", err))
		}

		cert, err := certificate.FromP12Bytes(bytes, p12password)
		if err != nil {
			log.Fatal(fmt.Sprintf("Error parsing certificate: %s", err))
		}

		developmentClient = apns2.NewClient(cert).Development()
		productionClient = apns2.NewClient(cert).Production()
	} else {
		cert, err := certificate.FromP12File(p12file, p12password)
		if err != nil {
			log.Fatal(fmt.Sprintf("Error loading certificate file: %s", err))
		}

		developmentClient = apns2.NewClient(cert).Development()
		productionClient = apns2.NewClient(cert).Production()
	}

	// We only want to add root CAs when we are using a client CA, and have a TLSClientConfig.
	if rootCAs != nil && developmentClient.HTTPClient.Transport.(*http2.Transport).TLSClientConfig != nil {
		developmentClient.HTTPClient.Transport.(*http2.Transport).TLSClientConfig.RootCAs = rootCAs
		productionClient.HTTPClient.Transport.(*http2.Transport).TLSClientConfig.RootCAs = rootCAs
	}

	// instrument the HTTP clients with Datadog APM
	httptrace.WrapClient(developmentClient.HTTPClient)
	httptrace.WrapClient(productionClient.HTTPClient)

	mux.HandleFunc("POST /relay-to/{environment}/{token}/{extra...}", handleApnNotification)
	mux.HandleFunc("GET /relay-to/_health", handleHealthCheck)

	messageChan = make(chan *Message, maxQueueSize)
	for i := 1; i <= maxWorkers; i++ {
		go apnNotificationsWorker(i, httpClient)
	}

	if _, err := os.Stat(tlsCrtFile); !os.IsNotExist(err) {
		log.Fatal(http.ListenAndServeTLS(":"+port, tlsCrtFile, tlsKeyFile, mux))
	} else {
		log.Fatal(http.ListenAndServe(":"+port, mux))
	}
}

func handleHealthCheck(writer http.ResponseWriter, request *http.Request) {
	requestLog := log.WithContext(request.Context())

	writer.WriteHeader(200)
	fmt.Println(writer, "OK")
	requestLog.Info("Health check OK")
}

func handleApnNotification(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	requestID := request.Header.Get("X-Request-ID")

	if requestID == "" {
		requestID = uuid.New().String()
	}

	span, _ := tracer.SpanFromContext(ctx)
	span.SetTag("request-id", requestID)

	requestLog := log.WithFields(log.Fields{"request-id": requestID}).WithContext(ctx)

	isProduction := request.PathValue("environment") == "production"

	notification := &apns2.Notification{}
	notification.DeviceToken = request.PathValue("token")

	buffer := new(bytes.Buffer)
	_, err := buffer.ReadFrom(request.Body)
	if err != nil {
		http.Error(writer, "Error reading request body", http.StatusInternalServerError)
		requestLog.Error(fmt.Sprintf("Error reading request body: %s", err))
		return
	}

	encodedString := encode85(buffer.Bytes())
	payload := payload.NewPayload().Alert("🎺").MutableContent().ContentAvailable().Custom("p", encodedString)

	extra := request.PathValue("extra")
	if extra != "" {
		payload.Custom("x", extra)
	}

	notification.Payload = payload
	notification.Topic = topic

	switch request.Header.Get("Content-Encoding") {
	case "aesgcm":
		if publicKey, err := encodedValue(request.Header, "Crypto-Key", "dh"); err == nil {
			payload.Custom("k", publicKey)
		} else {
			writer.WriteHeader(500)
			fmt.Println(writer, "Error retrieving public key:", err)
			requestLog.Error(fmt.Sprintf("Error retrieving public key: %s", err))
			return
		}

		if salt, err := encodedValue(request.Header, "Encryption", "salt"); err == nil {
			payload.Custom("s", salt)
		} else {
			writer.WriteHeader(500)
			fmt.Println(writer, "Error retrieving salt:", err)
			requestLog.Error(fmt.Sprintf("Error retrieving salt: %s", err))
			return
		}
	case "aes128gcm": // RFC8030+RFC8291+RFC8292 support. No further headers needed.
	default:
		writer.WriteHeader(415)
		fmt.Println(writer, "Unsupported Content-Encoding:", request.Header.Get("Content-Encoding"))
		requestLog.Error(fmt.Sprintf("Unsupported Content-Encoding: %s", request.Header.Get("Content-Encoding")))
		return
	}

	if seconds := request.Header.Get("TTL"); seconds != "" {
		if ttl, err := strconv.Atoi(seconds); err == nil {
			notification.Expiration = time.Now().Add(time.Duration(ttl) * time.Second)
		}
	}

	if topic := request.Header.Get("Topic"); topic != "" {
		notification.CollapseID = topic
	}

	switch request.Header.Get("Urgency") {
	case "very-low", "low":
		notification.Priority = apns2.PriorityLow
	default:
		notification.Priority = apns2.PriorityHigh
	}

	unsubscribeUrl := request.Header.Get("Unsubscribe-Url")

	messageChan <- &Message{isProduction, notification, unsubscribeUrl, requestLog, context.WithoutCancel(ctx)}

	// always reply w/ success, since we don't know how apple responded
	writer.WriteHeader(201)
}

func env(name, defaultValue string) string {
	if value, isPresent := os.LookupEnv(name); isPresent {
		return value
	} else {
		return defaultValue
	}
}

func encodedValue(header http.Header, name, key string) (string, error) {
	keyValues := parseKeyValues(header.Get(name))
	value, exists := keyValues[key]
	if !exists {
		return "", fmt.Errorf("value %s not found in header %s", key, name)
	}

	bytes, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}

	return encode85(bytes), nil
}

func parseKeyValues(values string) map[string]string {
	f := func(c rune) bool {
		return c == ';'
	}

	entries := strings.FieldsFunc(values, f)

	m := make(map[string]string)
	for _, entry := range entries {
		parts := strings.Split(entry, "=")
		m[parts[0]] = parts[1]
	}

	return m
}

var z85digits = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")

func encode85(bytes []byte) string {
	numBlocks := len(bytes) / 4
	suffixLength := len(bytes) % 4

	encodedLength := numBlocks * 5
	if suffixLength != 0 {
		encodedLength += suffixLength + 1
	}

	encodedBytes := make([]byte, encodedLength)

	src := bytes
	dest := encodedBytes
	for block := 0; block < numBlocks; block++ {
		value := binary.BigEndian.Uint32(src)

		for i := 0; i < 5; i++ {
			dest[4-i] = z85digits[value%85]
			value /= 85
		}

		src = src[4:]
		dest = dest[5:]
	}

	if suffixLength != 0 {
		value := 0

		for i := 0; i < suffixLength; i++ {
			value *= 256
			value |= int(src[i])
		}

		for i := 0; i < suffixLength+1; i++ {
			dest[suffixLength-i] = z85digits[value%85]
			value /= 85
		}
	}

	return string(encodedBytes)
}
