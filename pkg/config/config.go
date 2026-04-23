package config

import (
	"fmt"
	"io"
	"os"
	"time"

	"fortio.org/duration"
	"go.yaml.in/yaml/v4"
)

type CertKind int
type TimeDuration time.Duration
type OSFileMode os.FileMode

const (
	KindPrivateKey CertKind = iota
	KindCertificate
	KindPrivateCertChain
	KindPFX
	KindPrivateCert
	KindCertRootChain
)

const (
	DefaultConfigPath    = "config.yaml"
	DefaultRefreshPeriod = "1h"
	DefaultJobTimeout    = "5s"
	DefaultLogPath       = "/dev/stdout"
	DefaultLogLevel      = "info"
	DefaultStorePath     = "/etc/certwarden-client/certs/"
	DefaultKind          = KindPrivateCertChain
	DefaultPermissions   = 0640
)

var certKindName = map[string]CertKind{
	"privatekey":       KindPrivateKey,
	"certificate":      KindCertificate,
	"privatecertchain": KindPrivateCertChain,
	"pfx":              KindPFX,
	"privatecert":      KindPrivateCert,
	"certrootchain":    KindCertRootChain,
}

type Global struct {
	CertWardenURL string        `yaml:"certWardenURL"`
	RefreshPeriod *TimeDuration `yaml:"refreshPeriod"`
	JobTimeout    *TimeDuration `yaml:"jobTimeout"`
	StorePath     string        `yaml:"storePath"`
	LogPath       string        `yaml:"logPath"`
	LogLevel      string        `yaml:"logLevel"`
}

type Certificate struct {
	Name          string        `yaml:"name"`
	CertAPIToken  string        `yaml:"certAPIToken"`
	KeyAPIToken   string        `yaml:"keyAPIToken"`
	Kind          *CertKind     `yaml:"kind"`
	StorePath     string        `yaml:"storePath"`
	Permissions   *OSFileMode   `yaml:"permissions"`
	RefreshPeriod *TimeDuration `yaml:"refreshPeriod"`
	OnRefreshCmd  string        `yaml:"onRefreshCmd"`
}
type Config struct {
	Global       *Global        `yaml:"global"`
	Certificates []*Certificate `yaml:"certificates"`
}

func (d *TimeDuration) UnmarshalYAML(value *yaml.Node) error {
	switch value.Tag {
	case "!!str":
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}

		parsed, err := duration.Parse(s)
		if err != nil {
			return err
		}

		*d = TimeDuration(parsed)

	case "!!int":
		var i int64
		if err := value.Decode(&i); err != nil {
			return err
		}

		*d = TimeDuration(i)

	default:
		return fmt.Errorf("invalid duration format")
	}

	return nil
}

func (k *CertKind) UnmarshalYAML(value *yaml.Node) error {
	var kind string
	if err := value.Decode(&kind); err != nil {
		return err
	}
	*k = certKindName[kind]
	return nil
}

func (fm *OSFileMode) UnmarshalYAML(value *yaml.Node) error {
	var i int
	if err := value.Decode(&i); err != nil {
		return err
	}

	*fm = OSFileMode(os.FileMode(i))
	return nil
}

func (g *Global) SetDefaults() {
	if g.RefreshPeriod == nil {
		t, _ := duration.Parse(DefaultRefreshPeriod)
		g.RefreshPeriod = new(TimeDuration(t))
	}

	if g.JobTimeout == nil {
		t, _ := duration.Parse(DefaultJobTimeout)
		g.JobTimeout = new(TimeDuration(t))
	}

	if g.LogPath == "" {
		g.LogPath = DefaultLogPath
	}
	if g.LogLevel == "" {
		g.LogLevel = DefaultLogLevel
	}

	if g.StorePath == "" {
		g.StorePath = DefaultStorePath
	}
}

func (c *Certificate) SetDefaults() {
	if c.Kind == nil {
		c.Kind = new(DefaultKind)
	}

	if c.Permissions == nil {
		c.Permissions = new(OSFileMode(os.FileMode(DefaultPermissions)))
	}
}

func (c *Config) applyDefaults() {
	if c.Global == nil {
		c.Global = &Global{}
	}

	c.Global.SetDefaults()

	for i := range c.Certificates {
		c.Certificates[i].SetDefaults()
	}
}

func (c *Config) Load(path string) error {
	if path == "" {
		path = DefaultConfigPath
	}

	configFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func(configFile *os.File) {
		_ = configFile.Close()
	}(configFile)

	data, err := io.ReadAll(configFile)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, c)
	if err != nil {
		return err
	}

	c.applyDefaults()
	if c.Global.CertWardenURL == "" {
		return fmt.Errorf("global.certWardenURL is required")
	}
	return nil
}
