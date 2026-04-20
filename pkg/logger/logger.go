package logger

import (
	"certwarden-client/pkg/config"
	"os"

	"github.com/sirupsen/logrus"
)

var Log = logrus.New()

func SetupLogging(conf *config.Config) error {
	logLevel, err := logrus.ParseLevel(conf.Global.LogLevel)
	if err != nil {
		return err
	}
	Log.SetLevel(logLevel)
	if conf.Global.LogPath != "/dev/stdout" {
		logFile, err := os.OpenFile(conf.Global.LogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
		Log.SetOutput(logFile)
		logrus.RegisterExitHandler(func() {
			_ = logFile.Close()
		})
	} else {
		Log.SetOutput(os.Stdout)
	}

	return nil
}
