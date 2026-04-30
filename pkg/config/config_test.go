package config

import (
	"fmt"
	"io/fs"
	"testing"

	"fortio.org/duration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"
)

func TestTimeDurationUnmarshalYAML(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	var valueText = yaml.Node{
		Kind:          yaml.ScalarNode,
		Style:         0,
		Tag:           "!!str",
		Value:         "1w1d1h1m1s",
		Anchor:        "",
		Alias:         nil,
		Content:       nil,
		HeadComment:   "",
		LineComment:   "",
		FootComment:   "",
		Line:          3,
		Column:        18,
		Encoding:      yaml.EncodingAny,
		Version:       nil,
		TagDirectives: nil,
	}

	var valueInt = yaml.Node{
		Kind:          yaml.ScalarNode,
		Style:         0,
		Tag:           "!!int",
		Value:         "100",
		Anchor:        "",
		Alias:         nil,
		Content:       nil,
		HeadComment:   "",
		LineComment:   "",
		FootComment:   "",
		Line:          3,
		Column:        18,
		Encoding:      yaml.EncodingAny,
		Version:       nil,
		TagDirectives: nil,
	}

	var dur TimeDuration = 0

	err := dur.UnmarshalYAML(&valueText)
	requirements.NoErrorf(err, "failed to unmarshal string time to TimeDuration: %s", err)
	assertions.Equal(int64((1+60+3600+3600*24+3600*24*7)*1000000000), int64(dur), "invalid time value after unmarshal from string")

	err = dur.UnmarshalYAML(&valueInt)
	requirements.NoErrorf(err, "failed to unmarshal integer time to TimeDuration: %s", err)
	assertions.Equal(int64(100), int64(dur), "invalid time value after unmarshal from integer")
}

func TestCertKindUnmarshalYAML(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	var valueText = yaml.Node{
		Kind:          yaml.ScalarNode,
		Style:         0,
		Tag:           "!!str",
		Value:         "",
		Anchor:        "",
		Alias:         nil,
		Content:       nil,
		HeadComment:   "",
		LineComment:   "",
		FootComment:   "",
		Line:          3,
		Column:        18,
		Encoding:      yaml.EncodingAny,
		Version:       nil,
		TagDirectives: nil,
	}

	for key, value := range certKindName {
		valueText.Value = key
		var kind CertKind = -1
		err := kind.UnmarshalYAML(&valueText)
		requirements.NoErrorf(err, "failed to unmarshal CertKind: %s", err)
		assertions.Equalf(value, kind, "invalid CertKind after unmarshal")
	}

	valueText.Value = "privatecertchian"
	var kind CertKind = -1
	err := kind.UnmarshalYAML(&valueText)
	assertions.Error(err)
}

func TestOSFileModeUnmarshalYAML(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	var valueText = yaml.Node{
		Kind:          yaml.ScalarNode,
		Style:         0,
		Tag:           "!!str",
		Value:         "0644",
		Anchor:        "",
		Alias:         nil,
		Content:       nil,
		HeadComment:   "",
		LineComment:   "",
		FootComment:   "",
		Line:          3,
		Column:        18,
		Encoding:      yaml.EncodingAny,
		Version:       nil,
		TagDirectives: nil,
	}

	var valueInt = yaml.Node{
		Kind:          yaml.ScalarNode,
		Style:         0,
		Tag:           "!!int",
		Value:         "0644",
		Anchor:        "",
		Alias:         nil,
		Content:       nil,
		HeadComment:   "",
		LineComment:   "",
		FootComment:   "",
		Line:          3,
		Column:        18,
		Encoding:      yaml.EncodingAny,
		Version:       nil,
		TagDirectives: nil,
	}

	var perm OSFileMode
	err := perm.UnmarshalYAML(&valueText)
	assertions.Error(err)
	err = perm.UnmarshalYAML(&valueInt)
	requirements.NoErrorf(err, "failed to unmarshal OSFileMode: %s", err)
	assertions.Equal(OSFileMode(0644), perm, "invalid OSFileMode after unmarshal")
}

func TestGlobalSetDefaults(t *testing.T) {
	assertions := assert.New(t)

	refreshperiod, _ := duration.Parse(DefaultRefreshPeriod)
	jobtimeout, _ := duration.Parse(DefaultJobTimeout)
	var expected = Global{
		CertWardenURL: "",
		RefreshPeriod: new(TimeDuration(refreshperiod)),
		JobTimeout:    new(TimeDuration(jobtimeout)),
		StorePath:     DefaultStorePath,
		LogPath:       DefaultLogPath,
		LogLevel:      DefaultLogLevel,
	}

	actual := Global{}
	actual.SetDefaults()
	assertions.Equal(expected, actual)
}

func TestCertificateSetDefaults(t *testing.T) {
	assertions := assert.New(t)

	var expected = Certificate{
		Name:            "0",
		CertAPIToken:    "",
		KeyAPIToken:     "",
		Kind:            new(DefaultKind),
		StorePath:       "",
		Filename:        "0" + "_" + certKindDefaultBaseFilename[DefaultKind],
		FilenamePrefix:  "",
		SplitKeyAndCert: false,
		Permissions:     new(OSFileMode(DefaultPermissions)),
		RefreshPeriod:   nil,
		OnRefreshCmd:    "",
	}

	actual := Certificate{}
	actual.SetDefaults(0)
	assertions.Equal(expected, actual)
}

func TestConfigApplyDefaults(t *testing.T) {
	assertions := assert.New(t)

	refreshPeriod, _ := duration.Parse(DefaultRefreshPeriod)
	jobTimeout, _ := duration.Parse(DefaultJobTimeout)
	expected := Config{
		Global: &Global{
			CertWardenURL: "",
			RefreshPeriod: new(TimeDuration(refreshPeriod)),
			JobTimeout:    new(TimeDuration(jobTimeout)),
			StorePath:     DefaultStorePath,
			LogPath:       DefaultLogPath,
			LogLevel:      DefaultLogLevel,
		},
		Certificates: []*Certificate{
			{
				Name:            "0",
				CertAPIToken:    "",
				KeyAPIToken:     "",
				Kind:            new(DefaultKind),
				StorePath:       "",
				Filename:        "0" + "_" + certKindDefaultBaseFilename[DefaultKind],
				FilenamePrefix:  "",
				SplitKeyAndCert: false,
				Permissions:     new(OSFileMode(DefaultPermissions)),
				RefreshPeriod:   nil,
				OnRefreshCmd:    "",
			},
		},
	}
	actual := Config{Global: &Global{}, Certificates: []*Certificate{{}}}
	actual.applyDefaults()
	assertions.Equal(expected, actual)
}

func TestConfigLoadMissingFile(t *testing.T) {
	assertions := assert.New(t)

	conf := &Config{}
	err := conf.Load("../../test/configs/nonexistent.yaml")
	assertions.IsType(&fs.PathError{}, err)
}

func TestConfigLoadEmptyFile(t *testing.T) {
	assertions := assert.New(t)

	conf := &Config{}
	err := conf.Load("../../test/configs/emptyFile.yaml")
	assertions.EqualError(err, "global.certWardenURL is required")
}

func TestConfigLoadEmptyConfig(t *testing.T) {
	assertions := assert.New(t)

	conf := &Config{}
	err := conf.Load("../../test/configs/emptyConfig.yaml")
	assertions.EqualError(err, "global.certWardenURL is required")
}

func TestConfigLoadMalformedConfig(t *testing.T) {
	assertions := assert.New(t)

	conf := &Config{}
	err := conf.Load("../../test/configs/malformedConfig.yaml")
	assertions.IsType(&yaml.LoadErrors{}, err)
}

func TestConfigLoadFullConfig(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)

	conf := &Config{}
	err := conf.Load("../../test/configs/allOptionsConfig.yaml")
	requirements.NoErrorf(err, "failed to load config: %s", err)

	assertions.NotNil(conf.Global)
	assertions.Len(conf.Certificates, 7)
	assertions.Equal("https://example.com", conf.Global.CertWardenURL)
	assertions.Equal((*TimeDuration)(new(int64(694861000000000))), conf.Global.RefreshPeriod)
	assertions.Equal((*TimeDuration)(new(int64(5000000000))), conf.Global.JobTimeout)
	assertions.Equal("/etc/ssl", conf.Global.StorePath)
	assertions.Equal("/var/log/log.log", conf.Global.LogPath)
	assertions.Equal("debug", conf.Global.LogLevel)

	expectedPermissions := new(OSFileMode(0123))
	for testno, cert := range conf.Certificates {
		assertions.Equal(fmt.Sprintf("test%d", testno+1), cert.Name)
		assertions.Equal("CertToken", cert.CertAPIToken)
		assertions.Equal("KeyToken", cert.KeyAPIToken)
		assertions.Equal("/opt/certs", cert.StorePath)

		if testno < 6 {
			assertions.Equal(CertKind(testno), *cert.Kind)
			assertions.Equal(cert.Name+"_"+certKindDefaultBaseFilename[*cert.Kind], cert.Filename)
			assertions.Equal(false, cert.SplitKeyAndCert)
		} else {
			assertions.Equal(KindPrivateCertChain, *cert.Kind)
			assertions.Equal(true, cert.SplitKeyAndCert)
			assertions.Equal(cert.FilenamePrefix, cert.Filename)
		}

		assertions.Equal(expectedPermissions, cert.Permissions)
		assertions.Equal((*TimeDuration)(new(int64(10000000000))), cert.RefreshPeriod)
		assertions.Equal("command", cert.OnRefreshCmd)
	}
}
