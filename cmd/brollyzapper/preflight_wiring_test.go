package main

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/lnd"
)

// as0.11 criterion 7: production wires every preflight input.
//
// An unwired accessor renders its rows NOT CHECKED, which is the honest default
// for a report that was not given a way to ask — and on the box it would read as
// a guard or a node that never answered, indefinitely, with nothing red anywhere
// to say why. So the default is preflight's and the wiring is asserted here: a
// field serve() stops setting is a red gate, not a silent grey row.
//
// BY REFLECTION over every field, so a field added to Inputs later is held to
// this without anyone remembering to extend a list. Nothing is called: the
// sources are zero-valued, and a method value on a nil pointer is non-nil until
// it runs.
func TestProductionWiresEveryPreflightInput(t *testing.T) {
	sources := preflightSources{
		cfg:                &config.Server{DataDir: "/data"},
		unresolvedPayments: func(context.Context) (int, error) { return 0, nil },
		serverIP:           netip.MustParseAddr("10.21.0.17"),
		proxiesDeclared:    func() bool { return false },
		repair:             func(string) {},
	}
	brokerStatus := func(context.Context) (lnd.BrokerStatus, error) { return lnd.BrokerStatus{}, nil }

	in := reflect.ValueOf(sources.inputs(brokerStatus))
	for i := range in.NumField() {
		field, value := in.Type().Field(i), in.Field(i)
		switch {
		case field.Name == "ServerIP":
			// Discovered at startup, and legitimately absent when discovery fails —
			// a state its rows already say as not checked, with their own reason.
			continue
		case value.Kind() == reflect.Func && value.IsNil():
			t.Errorf("preflight.Inputs.%s is not wired; its rows would say not checked on every install", field.Name)
		case value.Kind() == reflect.String && value.String() == "":
			t.Errorf("preflight.Inputs.%s is empty; its row would say not checked on every install", field.Name)
		case value.Kind() != reflect.Func && value.Kind() != reflect.String:
			t.Errorf("preflight.Inputs.%s is a %s, which this test does not know how to call wired", field.Name, value.Kind())
		}
	}
}
