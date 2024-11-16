package grpc

import (
	prom_middleware "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	serverMetrics = prom_middleware.NewServerMetrics()
	clientMetrics = prom_middleware.NewClientMetrics()
)

func init() {
	prometheus.MustRegister(serverMetrics)
	prometheus.MustRegister(clientMetrics)
}
