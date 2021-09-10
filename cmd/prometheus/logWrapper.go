// Copyright 2021 Red Hat, Inc
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This package is a hack converting between the interfaces of two different loggers.
// See https://github.com/simonpasquier/klog-gokit/issues/20
// klog-gokit is supposed to be a drop in replacement for Kubernetes native logger.
// However, the two libraries rely on different underlying loggers and logger interfaces.
// Kubernetes relies on github.com/go-logr/logr while SimonPasquier relies on github.com/go-kit/log.
// Each logging implementation has its own interface and requires different methods to be implemneted.
// SimonPasquier seems to have been added to make the Kubernetes logger less noisy, which has more recently
// also been done in Istio using the Kubernetes logger.
package main

import (
	"fmt"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/go-logr/logr"
)

func logToLogr(wrapper log.Logger) logr.Logger {
	return logWrapper{
		Logger: &wrapper,
	}
}

type logWrapper struct {
	Logger *log.Logger
}

// Enabled tests whether this Logger is enabled.  For example, commandline
// flags might be used to set the logging verbosity and disable some info
// logs.
func (wrapper logWrapper) Enabled() bool {
	return true
}

// Info logs a non-error message with the given key/value pairs as context.
//
// The msg argument should be used to add some constant description to
// the wrapper line.  The key/value pairs can then be used to add additional
// variable information.  The key/value pairs should alternate string
// keys and arbitrary values.
func (wrapper logWrapper) Info(msg string, keysAndValues ...interface{}) {
	level.Info(*wrapper.Logger).Log(fmt.Sprintf(msg, keysAndValues...))
}

// Error logs an error, with the given message and key/value pairs as context.
// It functions similarly to calling Info with the "error" named value, but may
// have unique behavior, and should be preferred for logging errors (see the
// package documentations for more information).
//
// The msg field should be used to add context to any underlying error,
// while the err field should be used to attach the actual error that
// triggered this wrapper line, if present.
func (wrapper logWrapper) Error(err error, msg string, keysAndValues ...interface{}) {
	level.Error(*wrapper.Logger).Log(fmt.Sprintf(msg, keysAndValues...))
}

// V returns an Logger value for a specific verbosity level, relative to
// this Logger.  In other words, V values are additive.  V higher verbosity
// level means a wrapper message is less important.  It's illegal to pass a wrapper
// level less than zero.
func (wrapper logWrapper) V(inLevel int) logr.Logger {
	if inLevel == 0 {
		return logToLogr(level.Error(*wrapper.Logger))
	} else if inLevel == 1 {
		return logToLogr(level.Warn(*wrapper.Logger))
	} else if inLevel == 2 {
		return logToLogr(level.Info(*wrapper.Logger))
	} else {
		return logToLogr(level.Debug(*wrapper.Logger))
	}
}

// WithValues adds some key-value pairs of context to a logger.
// See Info for documentation on how key/value pairs work.
func (wrapper logWrapper) WithValues(keysAndValues ...interface{}) logr.Logger {
	return logToLogr(log.WithPrefix(*wrapper.Logger, keysAndValues...))
}

// WithName adds a new element to the logger's name.
// Successive calls with WithName continue to append
// suffixes to the logger's name.  It's strongly recommended
// that name segments contain only letters, digits, and hyphens
// (see the package documentation for more information).
func (wrapper logWrapper) WithName(name string) logr.Logger {
	return logToLogr(log.WithPrefix(*wrapper.Logger, name))
}
