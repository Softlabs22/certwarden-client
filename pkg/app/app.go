package app

import (
	"certwarden-client/pkg/config"
	"certwarden-client/pkg/logger"
	"certwarden-client/pkg/scheduler"
	"certwarden-client/pkg/worker"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func signalName(s os.Signal) string {
	if sig, ok := s.(syscall.Signal); ok {
		switch sig {
		case syscall.SIGINT:
			return "SIGINT"
		case syscall.SIGTERM:
			return "SIGTERM"
		}
	}
	return s.String()
}

func waitForSignal() {
	schan := make(chan os.Signal, 1)
	signal.Notify(schan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-schan
	logger.Log.Infof("Received %s (%v)", signalName(sig), sig)
}

func Run(conf *config.Config) error {
	var jobs []*worker.CertJob
	for _, cert := range conf.Certificates {
		var refreshPeriod = cert.RefreshPeriod
		if refreshPeriod == nil {
			refreshPeriod = conf.Global.RefreshPeriod
		}
		var storePath = cert.StorePath
		if storePath == "" {
			storePath = conf.Global.StorePath
		}
		job := &worker.CertJob{
			Name:         cert.Name,
			APIHostURL:   conf.Global.CertWardenURL,
			CertToken:    cert.CertAPIToken,
			KeyToken:     cert.KeyAPIToken,
			Kind:         *cert.Kind,
			SavePath:     storePath,
			Permissions:  (*os.FileMode)(cert.Permissions),
			OnRefreshCmd: cert.OnRefreshCmd,
			RunInterval:  time.Duration(*refreshPeriod),
			JobTimeout:   time.Duration(*conf.Global.JobTimeout),
		}
		jobs = append(jobs, job)
	}

	logger.Log.Info("Initializing job manager...")
	manager, err := scheduler.NewJobManager(jobs, 5)
	if err != nil {
		return err
	}
	manager.Start()

	logger.Log.Info("Ready, listening for signals")
	waitForSignal()
	logger.Log.Info("Shutting down")
	return nil
}
